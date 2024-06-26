// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: github.com/yext/cloudprober/targets/testdata/testdata.proto

package cloudprober_targets_testdata

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import proto1 "github.com/yext/cloudprober/targets/proto"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

type FancyTargets struct {
	Name                 *string  `protobuf:"bytes,1,req,name=name" json:"name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *FancyTargets) Reset()         { *m = FancyTargets{} }
func (m *FancyTargets) String() string { return proto.CompactTextString(m) }
func (*FancyTargets) ProtoMessage()    {}
func (*FancyTargets) Descriptor() ([]byte, []int) {
	return fileDescriptor_testdata_3eb7a7ec89906fb1, []int{0}
}
func (m *FancyTargets) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FancyTargets.Unmarshal(m, b)
}
func (m *FancyTargets) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FancyTargets.Marshal(b, m, deterministic)
}
func (dst *FancyTargets) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FancyTargets.Merge(dst, src)
}
func (m *FancyTargets) XXX_Size() int {
	return xxx_messageInfo_FancyTargets.Size(m)
}
func (m *FancyTargets) XXX_DiscardUnknown() {
	xxx_messageInfo_FancyTargets.DiscardUnknown(m)
}

var xxx_messageInfo_FancyTargets proto.InternalMessageInfo

func (m *FancyTargets) GetName() string {
	if m != nil && m.Name != nil {
		return *m.Name
	}
	return ""
}

var E_FancyTargets = &proto.ExtensionDesc{
	ExtendedType:  (*proto1.TargetsDef)(nil),
	ExtensionType: (*FancyTargets)(nil),
	Field:         200,
	Name:          "cloudprober.targets.testdata.fancy_targets",
	Tag:           "bytes,200,opt,name=fancy_targets,json=fancyTargets",
	Filename:      "github.com/yext/cloudprober/targets/testdata/testdata.proto",
}

func init() {
	proto.RegisterType((*FancyTargets)(nil), "cloudprober.targets.testdata.FancyTargets")
	proto.RegisterExtension(E_FancyTargets)
}

func init() {
	proto.RegisterFile("github.com/yext/cloudprober/targets/testdata/testdata.proto", fileDescriptor_testdata_3eb7a7ec89906fb1)
}

var fileDescriptor_testdata_3eb7a7ec89906fb1 = []byte{
	// 168 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xb2, 0x4e, 0xcf, 0x2c, 0xc9,
	0x28, 0x4d, 0xd2, 0x4b, 0xce, 0xcf, 0xd5, 0xaf, 0x4c, 0xad, 0x28, 0xd1, 0x4f, 0xce, 0xc9, 0x2f,
	0x4d, 0x29, 0x28, 0xca, 0x4f, 0x4a, 0x2d, 0xd2, 0x2f, 0x49, 0x2c, 0x4a, 0x4f, 0x2d, 0x29, 0xd6,
	0x2f, 0x49, 0x2d, 0x2e, 0x49, 0x49, 0x2c, 0x49, 0x84, 0x33, 0xf4, 0x0a, 0x8a, 0xf2, 0x4b, 0xf2,
	0x85, 0x64, 0x90, 0x14, 0xeb, 0x41, 0x15, 0xeb, 0xc1, 0xd4, 0x48, 0x99, 0x13, 0x63, 0x34, 0xd8,
	0x20, 0x18, 0x0f, 0x62, 0xac, 0x92, 0x12, 0x17, 0x8f, 0x5b, 0x62, 0x5e, 0x72, 0x65, 0x08, 0x44,
	0x54, 0x48, 0x88, 0x8b, 0x25, 0x2f, 0x31, 0x37, 0x55, 0x82, 0x51, 0x81, 0x49, 0x83, 0x33, 0x08,
	0xcc, 0xb6, 0x2a, 0xe4, 0xe2, 0x4d, 0x03, 0xa9, 0x89, 0x87, 0x6a, 0x15, 0x92, 0xd7, 0xc3, 0xe6,
	0x18, 0xa8, 0x11, 0x2e, 0xa9, 0x69, 0x12, 0x27, 0x18, 0x15, 0x18, 0x35, 0xb8, 0x8d, 0xb4, 0xf4,
	0xf0, 0x39, 0x5a, 0x0f, 0xd9, 0xe2, 0x20, 0x9e, 0x34, 0x24, 0x1e, 0x20, 0x00, 0x00, 0xff, 0xff,
	0xce, 0x30, 0xca, 0x07, 0x2b, 0x01, 0x00, 0x00,
}
