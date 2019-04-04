// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: github.com/yext/cloudprober/probes/external/proto/server.proto

package cloudprober_probes_external

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

// ProbeRequest is the message that cloudprober sends to the external probe
// server.
type ProbeRequest struct {
	// The unique identifier for this request.  This is unique across
	// an execution of the probe server.  It starts at 1.
	RequestId *int32 `protobuf:"varint,1,req,name=request_id,json=requestId" json:"request_id,omitempty"`
	// How long to allow for the execution of this request, in
	// milliseconds.  If the time limit is exceeded, the server
	// should abort the request, but *not* send back a reply.  The
	// client will have to do timeouts anyway.
	TimeLimit            *int32                 `protobuf:"varint,2,req,name=time_limit,json=timeLimit" json:"time_limit,omitempty"`
	Options              []*ProbeRequest_Option `protobuf:"bytes,3,rep,name=options" json:"options,omitempty"`
	XXX_NoUnkeyedLiteral struct{}               `json:"-"`
	XXX_unrecognized     []byte                 `json:"-"`
	XXX_sizecache        int32                  `json:"-"`
}

func (m *ProbeRequest) Reset()         { *m = ProbeRequest{} }
func (m *ProbeRequest) String() string { return proto.CompactTextString(m) }
func (*ProbeRequest) ProtoMessage()    {}
func (*ProbeRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_server_c60fe4a100072ce9, []int{0}
}
func (m *ProbeRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ProbeRequest.Unmarshal(m, b)
}
func (m *ProbeRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ProbeRequest.Marshal(b, m, deterministic)
}
func (dst *ProbeRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ProbeRequest.Merge(dst, src)
}
func (m *ProbeRequest) XXX_Size() int {
	return xxx_messageInfo_ProbeRequest.Size(m)
}
func (m *ProbeRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_ProbeRequest.DiscardUnknown(m)
}

var xxx_messageInfo_ProbeRequest proto.InternalMessageInfo

func (m *ProbeRequest) GetRequestId() int32 {
	if m != nil && m.RequestId != nil {
		return *m.RequestId
	}
	return 0
}

func (m *ProbeRequest) GetTimeLimit() int32 {
	if m != nil && m.TimeLimit != nil {
		return *m.TimeLimit
	}
	return 0
}

func (m *ProbeRequest) GetOptions() []*ProbeRequest_Option {
	if m != nil {
		return m.Options
	}
	return nil
}

type ProbeRequest_Option struct {
	Name                 *string  `protobuf:"bytes,1,req,name=name" json:"name,omitempty"`
	Value                *string  `protobuf:"bytes,2,req,name=value" json:"value,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ProbeRequest_Option) Reset()         { *m = ProbeRequest_Option{} }
func (m *ProbeRequest_Option) String() string { return proto.CompactTextString(m) }
func (*ProbeRequest_Option) ProtoMessage()    {}
func (*ProbeRequest_Option) Descriptor() ([]byte, []int) {
	return fileDescriptor_server_c60fe4a100072ce9, []int{0, 0}
}
func (m *ProbeRequest_Option) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ProbeRequest_Option.Unmarshal(m, b)
}
func (m *ProbeRequest_Option) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ProbeRequest_Option.Marshal(b, m, deterministic)
}
func (dst *ProbeRequest_Option) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ProbeRequest_Option.Merge(dst, src)
}
func (m *ProbeRequest_Option) XXX_Size() int {
	return xxx_messageInfo_ProbeRequest_Option.Size(m)
}
func (m *ProbeRequest_Option) XXX_DiscardUnknown() {
	xxx_messageInfo_ProbeRequest_Option.DiscardUnknown(m)
}

var xxx_messageInfo_ProbeRequest_Option proto.InternalMessageInfo

func (m *ProbeRequest_Option) GetName() string {
	if m != nil && m.Name != nil {
		return *m.Name
	}
	return ""
}

func (m *ProbeRequest_Option) GetValue() string {
	if m != nil && m.Value != nil {
		return *m.Value
	}
	return ""
}

// ProbeReply is the message that external probe server sends back to the
// cloudprober.
type ProbeReply struct {
	// The sequence number for this request.
	RequestId *int32 `protobuf:"varint,1,req,name=request_id,json=requestId" json:"request_id,omitempty"`
	// For a normal result, this is not present.
	// If it is present, it indicates that the probe failed.
	ErrorMessage *string `protobuf:"bytes,2,opt,name=error_message,json=errorMessage" json:"error_message,omitempty"`
	// The result of the probe. Cloudprober parses the payload to retrieve
	// variables from it. It expects variables in the following format:
	// var1 value1 (for example: total_errors 589)
	// TODO(manugarg): Add an option to export mapped variables, for example:
	// client-errors map:lang java:200 python:20 golang:3
	Payload              *string  `protobuf:"bytes,3,opt,name=payload" json:"payload,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ProbeReply) Reset()         { *m = ProbeReply{} }
func (m *ProbeReply) String() string { return proto.CompactTextString(m) }
func (*ProbeReply) ProtoMessage()    {}
func (*ProbeReply) Descriptor() ([]byte, []int) {
	return fileDescriptor_server_c60fe4a100072ce9, []int{1}
}
func (m *ProbeReply) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ProbeReply.Unmarshal(m, b)
}
func (m *ProbeReply) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ProbeReply.Marshal(b, m, deterministic)
}
func (dst *ProbeReply) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ProbeReply.Merge(dst, src)
}
func (m *ProbeReply) XXX_Size() int {
	return xxx_messageInfo_ProbeReply.Size(m)
}
func (m *ProbeReply) XXX_DiscardUnknown() {
	xxx_messageInfo_ProbeReply.DiscardUnknown(m)
}

var xxx_messageInfo_ProbeReply proto.InternalMessageInfo

func (m *ProbeReply) GetRequestId() int32 {
	if m != nil && m.RequestId != nil {
		return *m.RequestId
	}
	return 0
}

func (m *ProbeReply) GetErrorMessage() string {
	if m != nil && m.ErrorMessage != nil {
		return *m.ErrorMessage
	}
	return ""
}

func (m *ProbeReply) GetPayload() string {
	if m != nil && m.Payload != nil {
		return *m.Payload
	}
	return ""
}

func init() {
	proto.RegisterType((*ProbeRequest)(nil), "cloudprober.probes.external.ProbeRequest")
	proto.RegisterType((*ProbeRequest_Option)(nil), "cloudprober.probes.external.ProbeRequest.Option")
	proto.RegisterType((*ProbeReply)(nil), "cloudprober.probes.external.ProbeReply")
}

func init() {
	proto.RegisterFile("github.com/yext/cloudprober/probes/external/proto/server.proto", fileDescriptor_server_c60fe4a100072ce9)
}

var fileDescriptor_server_c60fe4a100072ce9 = []byte{
	// 257 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x8f, 0x41, 0x4e, 0xc3, 0x30,
	0x10, 0x45, 0x95, 0x86, 0x52, 0x65, 0x28, 0x1b, 0x8b, 0x85, 0x05, 0x42, 0xaa, 0xca, 0x26, 0x2b,
	0x1b, 0xf5, 0x00, 0xec, 0x41, 0x20, 0x90, 0x2f, 0x10, 0xb9, 0xcd, 0xa8, 0x18, 0xd9, 0x71, 0xb0,
	0x9d, 0xaa, 0xb9, 0x23, 0x87, 0x42, 0xb6, 0x1b, 0xa9, 0x2b, 0x58, 0x65, 0xfe, 0xfb, 0x3f, 0x7f,
	0xc6, 0xf0, 0xb4, 0x57, 0xe1, 0x73, 0xd8, 0xb2, 0x9d, 0x35, 0x7c, 0xc4, 0x63, 0xe0, 0x3b, 0x6d,
	0x87, 0xb6, 0x77, 0x76, 0x8b, 0x8e, 0xa7, 0x8f, 0xe7, 0x78, 0x0c, 0xe8, 0x3a, 0xa9, 0xa3, 0x0e,
	0x96, 0x7b, 0x74, 0x07, 0x74, 0x2c, 0x09, 0x72, 0x77, 0x96, 0x67, 0x39, 0xcf, 0xa6, 0xfc, 0xfa,
	0xa7, 0x80, 0xe5, 0x47, 0x64, 0x02, 0xbf, 0x07, 0xf4, 0x81, 0xdc, 0x03, 0xb8, 0x3c, 0x36, 0xaa,
	0xa5, 0xc5, 0x6a, 0x56, 0xcf, 0x45, 0x75, 0x22, 0xcf, 0x6d, 0xb4, 0x83, 0x32, 0xd8, 0x68, 0x65,
	0x54, 0xa0, 0xb3, 0x6c, 0x47, 0xf2, 0x1a, 0x01, 0x79, 0x81, 0x85, 0xed, 0x83, 0xb2, 0x9d, 0xa7,
	0xe5, 0xaa, 0xac, 0xaf, 0x36, 0x8f, 0xec, 0x8f, 0xed, 0xec, 0x7c, 0x33, 0x7b, 0x4f, 0x3f, 0x8a,
	0xa9, 0xe0, 0x76, 0x03, 0x97, 0x19, 0x11, 0x02, 0x17, 0x9d, 0x34, 0x98, 0xae, 0xa9, 0x44, 0x9a,
	0xc9, 0x0d, 0xcc, 0x0f, 0x52, 0x0f, 0x98, 0x6e, 0xa8, 0x44, 0x16, 0xeb, 0x2f, 0x80, 0x53, 0x67,
	0xaf, 0xc7, 0xff, 0xde, 0xf2, 0x00, 0xd7, 0xe8, 0x9c, 0x75, 0x8d, 0x41, 0xef, 0xe5, 0x3e, 0x56,
	0x15, 0x75, 0x25, 0x96, 0x09, 0xbe, 0x65, 0x46, 0x28, 0x2c, 0x7a, 0x39, 0x6a, 0x2b, 0x5b, 0x5a,
	0x26, 0x7b, 0x92, 0xbf, 0x01, 0x00, 0x00, 0xff, 0xff, 0xda, 0xb1, 0x6d, 0x22, 0x98, 0x01, 0x00,
	0x00,
}
