// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: github.com/yext/cloudprober/targets/rtc/rtcreporter/proto/rtcreporter.proto

package cloudprober_targets_rtcreporter

import proto "github.com/golang/protobuf/proto"
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

type RtcReportOptions struct {
	// RTC configs which cloudprober should report itself to.
	Cfgs []string `protobuf:"bytes,1,rep,name=cfgs" json:"cfgs,omitempty"`
	// RTC rate at which cloudprober should report itself.
	IntervalMsec *int32 `protobuf:"varint,2,opt,name=interval_msec,json=intervalMsec,def=10000" json:"interval_msec,omitempty"`
	// Which system variables should be reported. For more information see
	// cloudprober/util. The sysVars dictionary contains variable names mapped to
	// their values. variables should be a list of the variable names that should
	// be reported (such as public/private ips).
	Variables []string `protobuf:"bytes,3,rep,name=variables" json:"variables,omitempty"`
	// Which groups this instance is a member of. See RtcTargetInfo.group for
	// more info.
	Groups               []string `protobuf:"bytes,4,rep,name=groups" json:"groups,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *RtcReportOptions) Reset()         { *m = RtcReportOptions{} }
func (m *RtcReportOptions) String() string { return proto.CompactTextString(m) }
func (*RtcReportOptions) ProtoMessage()    {}
func (*RtcReportOptions) Descriptor() ([]byte, []int) {
	return fileDescriptor_rtcreporter_24ab43802f99419a, []int{0}
}
func (m *RtcReportOptions) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_RtcReportOptions.Unmarshal(m, b)
}
func (m *RtcReportOptions) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_RtcReportOptions.Marshal(b, m, deterministic)
}
func (dst *RtcReportOptions) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RtcReportOptions.Merge(dst, src)
}
func (m *RtcReportOptions) XXX_Size() int {
	return xxx_messageInfo_RtcReportOptions.Size(m)
}
func (m *RtcReportOptions) XXX_DiscardUnknown() {
	xxx_messageInfo_RtcReportOptions.DiscardUnknown(m)
}

var xxx_messageInfo_RtcReportOptions proto.InternalMessageInfo

const Default_RtcReportOptions_IntervalMsec int32 = 10000

func (m *RtcReportOptions) GetCfgs() []string {
	if m != nil {
		return m.Cfgs
	}
	return nil
}

func (m *RtcReportOptions) GetIntervalMsec() int32 {
	if m != nil && m.IntervalMsec != nil {
		return *m.IntervalMsec
	}
	return Default_RtcReportOptions_IntervalMsec
}

func (m *RtcReportOptions) GetVariables() []string {
	if m != nil {
		return m.Variables
	}
	return nil
}

func (m *RtcReportOptions) GetGroups() []string {
	if m != nil {
		return m.Groups
	}
	return nil
}

// RtcTargetInfo is used by RTC targets. Hosts report all the ways they may be
// addressed to an RTC configuration, which will later be used as target
// information.
// The rtcreporter package is responsible for creating and sending these
// protobufs, while the rtc targets type of the targets package will receive
// these protobufs.
type RtcTargetInfo struct {
	// Name of host. Also used as variable name in the RTC config.
	InstanceName *string `protobuf:"bytes,1,opt,name=instance_name,json=instanceName" json:"instance_name,omitempty"`
	// List of tags this host belongs to, in order to filter out groups of related
	// hosts. For instance, maybe an rtc lister will only include instances that
	// have the group tag "DMZ_1". Instances may belong to multiple groups.
	Groups []string `protobuf:"bytes,2,rep,name=groups" json:"groups,omitempty"`
	// List of all ways this host can be addressed (such as public / private ip).
	Addresses            []*RtcTargetInfo_Address `protobuf:"bytes,3,rep,name=addresses" json:"addresses,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                 `json:"-"`
	XXX_unrecognized     []byte                   `json:"-"`
	XXX_sizecache        int32                    `json:"-"`
}

func (m *RtcTargetInfo) Reset()         { *m = RtcTargetInfo{} }
func (m *RtcTargetInfo) String() string { return proto.CompactTextString(m) }
func (*RtcTargetInfo) ProtoMessage()    {}
func (*RtcTargetInfo) Descriptor() ([]byte, []int) {
	return fileDescriptor_rtcreporter_24ab43802f99419a, []int{1}
}
func (m *RtcTargetInfo) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_RtcTargetInfo.Unmarshal(m, b)
}
func (m *RtcTargetInfo) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_RtcTargetInfo.Marshal(b, m, deterministic)
}
func (dst *RtcTargetInfo) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RtcTargetInfo.Merge(dst, src)
}
func (m *RtcTargetInfo) XXX_Size() int {
	return xxx_messageInfo_RtcTargetInfo.Size(m)
}
func (m *RtcTargetInfo) XXX_DiscardUnknown() {
	xxx_messageInfo_RtcTargetInfo.DiscardUnknown(m)
}

var xxx_messageInfo_RtcTargetInfo proto.InternalMessageInfo

func (m *RtcTargetInfo) GetInstanceName() string {
	if m != nil && m.InstanceName != nil {
		return *m.InstanceName
	}
	return ""
}

func (m *RtcTargetInfo) GetGroups() []string {
	if m != nil {
		return m.Groups
	}
	return nil
}

func (m *RtcTargetInfo) GetAddresses() []*RtcTargetInfo_Address {
	if m != nil {
		return m.Addresses
	}
	return nil
}

type RtcTargetInfo_Address struct {
	// "Name" of this address. An rtc lister may only include, for instance,
	// public ip addresses. It will filter out all Addresses that do not have
	// "PUBLIC_IP" as their tag.
	Tag *string `protobuf:"bytes,1,opt,name=tag" json:"tag,omitempty"`
	// Address contents.
	Address              *string  `protobuf:"bytes,2,opt,name=address" json:"address,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *RtcTargetInfo_Address) Reset()         { *m = RtcTargetInfo_Address{} }
func (m *RtcTargetInfo_Address) String() string { return proto.CompactTextString(m) }
func (*RtcTargetInfo_Address) ProtoMessage()    {}
func (*RtcTargetInfo_Address) Descriptor() ([]byte, []int) {
	return fileDescriptor_rtcreporter_24ab43802f99419a, []int{1, 0}
}
func (m *RtcTargetInfo_Address) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_RtcTargetInfo_Address.Unmarshal(m, b)
}
func (m *RtcTargetInfo_Address) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_RtcTargetInfo_Address.Marshal(b, m, deterministic)
}
func (dst *RtcTargetInfo_Address) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RtcTargetInfo_Address.Merge(dst, src)
}
func (m *RtcTargetInfo_Address) XXX_Size() int {
	return xxx_messageInfo_RtcTargetInfo_Address.Size(m)
}
func (m *RtcTargetInfo_Address) XXX_DiscardUnknown() {
	xxx_messageInfo_RtcTargetInfo_Address.DiscardUnknown(m)
}

var xxx_messageInfo_RtcTargetInfo_Address proto.InternalMessageInfo

func (m *RtcTargetInfo_Address) GetTag() string {
	if m != nil && m.Tag != nil {
		return *m.Tag
	}
	return ""
}

func (m *RtcTargetInfo_Address) GetAddress() string {
	if m != nil && m.Address != nil {
		return *m.Address
	}
	return ""
}

func init() {
	proto.RegisterType((*RtcReportOptions)(nil), "cloudprober.targets.rtcreporter.RtcReportOptions")
	proto.RegisterType((*RtcTargetInfo)(nil), "cloudprober.targets.rtcreporter.RtcTargetInfo")
	proto.RegisterType((*RtcTargetInfo_Address)(nil), "cloudprober.targets.rtcreporter.RtcTargetInfo.Address")
}

func init() {
	proto.RegisterFile("github.com/yext/cloudprober/targets/rtc/rtcreporter/proto/rtcreporter.proto", fileDescriptor_rtcreporter_24ab43802f99419a)
}

var fileDescriptor_rtcreporter_24ab43802f99419a = []byte{
	// 294 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x50, 0xcd, 0x4a, 0x03, 0x31,
	0x10, 0x26, 0xfd, 0xb1, 0x6c, 0xb4, 0x50, 0x72, 0x90, 0x20, 0x82, 0xa5, 0x5e, 0x8a, 0x87, 0xec,
	0x2a, 0xe8, 0xc1, 0x9b, 0x47, 0x11, 0x15, 0x42, 0xef, 0x25, 0x4d, 0xa7, 0xeb, 0x42, 0x77, 0xb3,
	0x4c, 0x66, 0x8b, 0xbe, 0x81, 0xaf, 0xe8, 0xdb, 0xc8, 0xa6, 0x29, 0x5d, 0x4f, 0x1e, 0x02, 0xf9,
	0xbe, 0x99, 0xef, 0x87, 0xe1, 0x2f, 0x79, 0x41, 0x1f, 0xcd, 0x4a, 0x59, 0x57, 0xa6, 0x5f, 0xf0,
	0x49, 0xa9, 0xdd, 0xba, 0x66, 0x5d, 0xa3, 0x5b, 0x01, 0xa6, 0x64, 0x30, 0x07, 0xf2, 0x29, 0x92,
	0x6d, 0x1f, 0x42, 0xed, 0x90, 0x00, 0xd3, 0x1a, 0x1d, 0xb9, 0x2e, 0xa3, 0x02, 0x23, 0xae, 0x3a,
	0x62, 0x15, 0xc5, 0xaa, 0xb3, 0x36, 0xfb, 0x66, 0x7c, 0xa2, 0xc9, 0xea, 0x80, 0xdf, 0x6b, 0x2a,
	0x5c, 0xe5, 0x85, 0xe0, 0x03, 0xbb, 0xc9, 0xbd, 0x64, 0xd3, 0xfe, 0x3c, 0xd1, 0xe1, 0x2f, 0x6e,
	0xf8, 0xb8, 0xa8, 0x08, 0x70, 0x67, 0xb6, 0xcb, 0xd2, 0x83, 0x95, 0xbd, 0x29, 0x9b, 0x0f, 0x1f,
	0x87, 0xb7, 0x59, 0x96, 0x65, 0xfa, 0xec, 0x30, 0x7b, 0xf5, 0x60, 0xc5, 0x25, 0x4f, 0x76, 0x06,
	0x0b, 0xb3, 0xda, 0x82, 0x97, 0xfd, 0x60, 0x72, 0x24, 0xc4, 0x39, 0x3f, 0xc9, 0xd1, 0x35, 0xb5,
	0x97, 0x83, 0x30, 0x8a, 0x68, 0xf6, 0xc3, 0xf8, 0x58, 0x93, 0x5d, 0x84, 0x96, 0xcf, 0xd5, 0xc6,
	0x89, 0xeb, 0x36, 0xd3, 0x93, 0xa9, 0x2c, 0x2c, 0x2b, 0x53, 0x82, 0x64, 0x53, 0x36, 0x4f, 0xda,
	0xb0, 0x3d, 0xf9, 0x66, 0x4a, 0xe8, 0xd8, 0xf5, 0xba, 0x76, 0x62, 0xc1, 0x13, 0xb3, 0x5e, 0x23,
	0x78, 0x1f, 0x4b, 0x9c, 0xde, 0x3d, 0xa8, 0x7f, 0xce, 0xa1, 0xfe, 0xe4, 0xab, 0xa7, 0xbd, 0x5e,
	0x1f, 0x8d, 0x2e, 0xee, 0xf9, 0x28, 0xb2, 0x62, 0xc2, 0xfb, 0x64, 0xf2, 0xd8, 0xa9, 0xfd, 0x0a,
	0xc9, 0x47, 0x71, 0x33, 0x5c, 0x27, 0xd1, 0x07, 0xf8, 0x1b, 0x00, 0x00, 0xff, 0xff, 0x14, 0xc7,
	0xea, 0x74, 0xd5, 0x01, 0x00, 0x00,
}
