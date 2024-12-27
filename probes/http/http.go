// Copyright 2017-2019 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package http implements HTTP probe type.
package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yext/cloudprober/logger"
	"github.com/yext/cloudprober/metrics"
	configpb "github.com/yext/cloudprober/probes/http/proto"
	"github.com/yext/cloudprober/probes/options"
	"golang.org/x/crypto/ocsp"
)

const (
	maxResponseSizeForMetrics = 128
	targetsUpdateInterval     = 1 * time.Minute
)

// Probe holds aggregate information about all probe runs, per-target.
type Probe struct {
	name   string
	opts   *options.Options
	c      *configpb.ProbeConf
	l      *logger.Logger
	client *http.Client

	// book-keeping params
	targets      []string
	httpRequests map[string]*http.Request
	results      map[string]*result
	protocol     string
	method       string
	url          string

	// Run counter, used to decide when to update targets or export
	// stats.
	runCnt int64

	// How often to resolve targets (in probe counts), initialized to
	// targetsUpdateInterval / p.opts.Interval. Targets and associated data
	// structures are updated when (runCnt % targetsUpdateFrequency) == 0
	targetsUpdateFrequency int64

	// How often to export metrics (in probe counts), initialized to
	// statsExportInterval / p.opts.Interval. Metrics are exported when
	// (runCnt % statsExportFrequency) == 0
	statsExportFrequency int64
}

type result struct {
	total, success, timeouts, dnsErrors, sslErrors int64
	latency                                        metrics.Value
	respCodes                                      *metrics.Map
	respBodies                                     *metrics.Map
	validationFailure                              *metrics.Map
}

// Init initializes the probe with the given params.
func (p *Probe) Init(name string, opts *options.Options) error {
	c, ok := opts.ProbeConf.(*configpb.ProbeConf)
	if !ok {
		return fmt.Errorf("not http config")
	}
	p.name = name
	p.opts = opts
	if p.l = opts.Logger; p.l == nil {
		p.l = &logger.Logger{}
	}
	p.c = c

	p.protocol = strings.ToLower(p.c.GetProtocol().String())
	p.method = p.c.GetMethod().String()

	p.url = p.c.GetRelativeUrl()
	if len(p.url) > 0 && p.url[0] != '/' {
		return fmt.Errorf("Invalid Relative URL: %s, must begin with '/'", p.url)
	}

	if p.c.GetIntegrityCheckPattern() != "" {
		p.l.Warningf("integrity_check_pattern field is now deprecated and doesn't do anything.")
	}

	if p.c.GetRequestsPerProbe() != 1 {
		p.l.Warningf("requests_per_probe field is now deprecated and will be removed in future releases.")
	}

	// Create a transport for our use. This is mostly based on
	// http.DefaultTransport with some timeouts changed.
	// TODO(manugarg): Considering cloning DefaultTransport once
	// https://github.com/golang/go/issues/26013 is fixed.
	dialer := &net.Dialer{
		Timeout:   p.opts.Timeout,
		KeepAlive: 30 * time.Second, // TCP keep-alive
		DualStack: true,
	}

	if p.opts.SourceIP != nil {
		dialer.LocalAddr = &net.TCPAddr{
			IP: p.opts.SourceIP,
		}
	}

	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         dialer.DialContext,
		MaxIdleConns:        256, // http.DefaultTransport.MaxIdleConns: 100.
		TLSHandshakeTimeout: p.opts.Timeout,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify:    p.c.GetDisableCertValidation(),
			VerifyPeerCertificate: CheckForRevokedCert,
		},
	}

	// If HTTP keep-alives are not enabled (default), disable HTTP keep-alive in
	// transport.
	if !p.c.GetKeepAlive() {
		transport.DisableKeepAlives = true
	} else {
		// If it's been more than 2 probe intervals since connection was used, close it.
		transport.IdleConnTimeout = 2 * p.opts.Interval
	}

	if p.c.GetDisableHttp2() {
		// HTTP/2 is enabled by default if server supports it. Setting TLSNextProto
		// to an empty dict is the only to disable it.
		transport.TLSNextProto = make(map[string]func(string, *tls.Conn) http.RoundTripper)
	}

	// Clients are safe for concurrent use by multiple goroutines.
	p.client = &http.Client{
		Transport: transport,
	}

	p.statsExportFrequency = int64(p.c.GetStatsExportIntervalMsec()) * 1e6 / p.opts.Interval.Nanoseconds()
	if p.statsExportFrequency == 0 {
		p.statsExportFrequency = 1
	}

	// Update targets and associated data structures (requests and results) once
	// in Init(). It's also called periodically in Start(), at
	// targetsUpdateInterval.
	p.updateTargets()
	p.targetsUpdateFrequency = targetsUpdateInterval.Nanoseconds() / p.opts.Interval.Nanoseconds()
	if p.targetsUpdateFrequency == 0 {
		p.targetsUpdateFrequency = 1
	}

	return nil
}

func CheckForRevokedCert(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(rawCerts) == 0 || len(verifiedChains) == 0 || len(verifiedChains[0]) < 2 {
		return fmt.Errorf("missing cert or issuer")
	}

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("failed to parse leaf certificate: %v", err)
	}

	if len(cert.OCSPServer) == 0 {
		return fmt.Errorf("no OCSP server URL found in certificate")
	}

	issuer := verifiedChains[0][1] // Second certificate in the chain is the issuer
	ocspRequest, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return fmt.Errorf("failed to create OCSP request: %v", err)
	}

	ocspURL := cert.OCSPServer[0]
	resp, err := http.Post(ocspURL, "application/ocsp-request", bytes.NewReader(ocspRequest))
	if err != nil {
		return fmt.Errorf("failed to query OCSP server: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("OCSP server returned status: %s", resp.Status)
	}

	ocspResponseData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read OCSP response: %v", err)
	}

	ocspResponse, err := ocsp.ParseResponse(ocspResponseData, issuer)
	if err != nil {
		return fmt.Errorf("failed to parse OCSP response: %v", err)
	}

	// Check for Revoked Status
	if ocspResponse.Status == ocsp.Revoked {
		return fmt.Errorf("tls: certificate is revoked")
	}

	return nil
}

// Return true if the underlying error indicates a http.Client timeout.
//
// Use for errors returned from http.Client methods (Get, Post).
func isClientTimeout(err error) bool {
	if uerr, ok := err.(*url.Error); ok {
		if nerr, ok := uerr.Err.(net.Error); ok && nerr.Timeout() {
			return true
		}
	}
	return false
}

// Return true if the underlying error indicates a SSL certificate verification error.
//
// Use for errors returned from http.Client methods (Get, Post).
func isSSLError(err error) bool {
	if err == nil {
		return false
	}

	if uerr, ok := err.(*url.Error); ok {
		switch uerr.Err.(type) {
		case x509.CertificateInvalidError, x509.HostnameError, x509.UnknownAuthorityError:
			return true
		case tls.RecordHeaderError:
			return true
		}

		// In the case of handshake errors, Go does not have a predefined
		// typed error. So use prefix matching to catch these errors.
		if strings.HasPrefix(uerr.Err.Error(), "tls: ") {
			return true
		}
	}

	return false
}

// Return true if the underlying error indicates a DNS lookup error.
//
// Use for errors returned from http.Client methods (Get, Post).
func isDNSError(err error) bool {
	if uerr, ok := err.(*url.Error); ok {
		if operr, ok := uerr.Err.(*net.OpError); ok {
			if _, ok := operr.Err.(*net.DNSError); ok {
				return true
			}
		}
	}
	return false
}

// httpRequest executes an HTTP request and updates the provided result struct.
func (p *Probe) doHTTPRequest(req *http.Request, result *result) {
	start := time.Now()
	result.total++

	resp, err := p.client.Do(req)
	latency := time.Since(start)

	if err != nil {
		if isClientTimeout(err) {
			p.l.Warning("Target:", req.Host, ", URL:", req.URL.String(), ", http.doHTTPRequest: timeout error: ", err.Error())
			result.timeouts++
			return
		}
		if isDNSError(err) {
			p.l.Warning("Target:", req.Host, ", URL:", req.URL.String(), ", http.doHTTPRequest: DNS error: ", err.Error())
			result.dnsErrors++
			return
		}
		if isSSLError(err) {
			p.l.Warning("Target:", req.Host, ", URL:", req.URL.String(), ", http.doHTTPRequest: SSL error: ", err.Error())
			result.sslErrors++
			return
		}
		p.l.Warning("Target:", req.Host, ", URL:", req.URL.String(), ", http.doHTTPRequest: ", err.Error())
		return
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		p.l.Warning("Target:", req.Host, ", URL:", req.URL.String(), ", http.doHTTPRequest: ", err.Error())
		return
	}

	// Calling Body.Close() allows the TCP connection to be reused.
	resp.Body.Close()
	result.respCodes.IncKey(strconv.FormatInt(int64(resp.StatusCode), 10))

	if p.opts.Validators != nil {
		var failedValidations []string

		for _, v := range p.opts.Validators {
			success, err := v.Validate(resp, respBody)
			if err != nil {
				p.l.Error("Error while running the validator ", v.Name, ": ", err.Error())
				continue
			}
			if !success {
				result.validationFailure.IncKey(v.Name)
				failedValidations = append(failedValidations, v.Name)
			}
		}

		// If any validation failed, return now, leaving the success and latency
		// counters unchanged.
		if len(failedValidations) > 0 {
			p.l.Debug("Target:", req.Host, ", URL:", req.URL.String(), ", http.doHTTPRequest: failed validations: ", strings.Join(failedValidations, ","))
			return
		}
	}

	result.success++
	result.latency.AddFloat64(latency.Seconds() / p.opts.LatencyUnit.Seconds())
	if p.c.GetExportResponseAsMetrics() {
		if len(respBody) <= maxResponseSizeForMetrics {
			result.respBodies.IncKey(string(respBody))
		}
	}
}

func (p *Probe) updateTargets() {
	p.targets = p.opts.Targets.List()

	if p.httpRequests == nil {
		p.httpRequests = make(map[string]*http.Request, len(p.targets))
	}

	if p.results == nil {
		p.results = make(map[string]*result, len(p.targets))
	}

	for _, target := range p.targets {
		// Update HTTP request
		req := p.httpRequestForTarget(target)
		if req != nil {
			p.httpRequests[target] = req
		}

		// Add missing result objects
		if p.results[target] == nil {
			var latencyValue metrics.Value
			if p.opts.LatencyDist != nil {
				latencyValue = p.opts.LatencyDist.Clone()
			} else {
				latencyValue = metrics.NewFloat(0)
			}
			p.results[target] = &result{
				latency:           latencyValue,
				respCodes:         metrics.NewMap("code", metrics.NewInt(0)),
				respBodies:        metrics.NewMap("resp", metrics.NewInt(0)),
				validationFailure: metrics.NewMap("validator", metrics.NewInt(0)),
			}
		}
	}
}

func (p *Probe) runProbe(ctx context.Context) {
	wg := sync.WaitGroup{}
	for _, target := range p.targets {
		req := p.httpRequests[target]
		if req == nil {
			continue
		}

		wg.Add(1)

		// Launch a separate goroutine for each target.
		go func(target string, req *http.Request) {
			defer wg.Done()

			// Spread out http requests over the probes time interval.
			if p.opts.Interval-p.opts.Timeout > 0 {
				time.Sleep(time.Duration(rand.Int63n(int64(p.opts.Interval - p.opts.Timeout))))
			}

			reqCtx, cancelReqCtx := context.WithTimeout(ctx, p.opts.Timeout)
			defer cancelReqCtx()

			numRequests := int32(0)
			for {
				p.doHTTPRequest(req.WithContext(reqCtx), p.results[target])

				numRequests++
				if numRequests >= p.c.GetRequestsPerProbe() {
					break
				}
				// Sleep for requests_interval_msec before continuing.
				time.Sleep(time.Duration(p.c.GetRequestsIntervalMsec()) * time.Millisecond)
			}
		}(target, req)
	}

	// Wait until all probes are done.
	wg.Wait()
}

// Start starts and runs the probe indefinitely.
func (p *Probe) Start(ctx context.Context, dataChan chan *metrics.EventMetrics) {
	for ts := range time.Tick(p.opts.Interval) {
		// Don't run another probe if context is canceled already.
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Update targets if its the turn for that.
		if (p.runCnt % p.targetsUpdateFrequency) == 0 {
			p.updateTargets()
		}
		p.runCnt++

		p.runProbe(ctx)

		if (p.runCnt % p.statsExportFrequency) == 0 {
			for _, target := range p.targets {
				result := p.results[target]
				em := metrics.NewEventMetrics(ts).
					AddMetric("total", metrics.NewInt(result.total)).
					AddMetric("success", metrics.NewInt(result.success)).
					AddMetric("latency", result.latency).
					AddMetric("timeouts", metrics.NewInt(result.timeouts)).
					AddMetric("dns-errors", metrics.NewInt(result.dnsErrors)).
					AddMetric("ssl-errors", metrics.NewInt(result.sslErrors)).
					AddMetric("resp-code", result.respCodes).
					AddMetric("resp-body", result.respBodies).
					AddLabel("ptype", "http").
					AddLabel("probe", p.name).
					AddLabel("dst", target)

				if p.opts.Validators != nil {
					em.AddMetric("validation_failure", result.validationFailure)
				}

				p.opts.LogMetrics(em)
				dataChan <- em
			}
		}
	}
}
