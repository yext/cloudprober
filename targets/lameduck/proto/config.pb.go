// Code generated by protoc-gen-go. DO NOT EDIT.
// source: github.com/yext/cloudprober/targets/lameduck/proto/config.proto

package proto

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
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type Options struct {
	// How often to check for lame-ducked targets
	ReEvalSec *int32 `protobuf:"varint,1,opt,name=re_eval_sec,json=reEvalSec,def=10" json:"re_eval_sec,omitempty"`
	// Runtime config project. If running on GCE, this defaults to the project
	// containing the VM.
	RuntimeconfigProject *string `protobuf:"bytes,2,opt,name=runtimeconfig_project,json=runtimeconfigProject" json:"runtimeconfig_project,omitempty"`
	// Lame duck targets runtime config name. An operator will create a variable
	// here to mark a target as lame-ducked.
	// TODO(izzycecil): This name needs to be changed.
	RuntimeconfigName *string `protobuf:"bytes,3,opt,name=runtimeconfig_name,json=runtimeconfigName,def=lame-duck-targets" json:"runtimeconfig_name,omitempty"`
	// Lame duck expiration time. We ignore variables (targets) that have been
	// updated more than these many seconds ago. This is a safety mechanism for
	// failing to cleanup. Also, the idea is that if a target has actually
	// disappeared, automatic targets expansion will take care of that some time
	// during this expiration period.
	ExpirationSec *int32 `protobuf:"varint,4,opt,name=expiration_sec,json=expirationSec,def=300" json:"expiration_sec,omitempty"`
	// Use an RDS client to get lame-duck-targets.
	UseRds *bool `protobuf:"varint,5,opt,name=use_rds,json=useRds" json:"use_rds,omitempty"`
	// Use an RDS server address
	RdsServerAddr        *string  `protobuf:"bytes,6,opt,name=rds_server_addr,json=rdsServerAddr,def=localhost:9314" json:"rds_server_addr,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Options) Reset()         { *m = Options{} }
func (m *Options) String() string { return proto.CompactTextString(m) }
func (*Options) ProtoMessage()    {}
func (*Options) Descriptor() ([]byte, []int) {
	return fileDescriptor_config_0b9e4b76d3ac140e, []int{0}
}
func (m *Options) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Options.Unmarshal(m, b)
}
func (m *Options) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Options.Marshal(b, m, deterministic)
}
func (dst *Options) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Options.Merge(dst, src)
}
func (m *Options) XXX_Size() int {
	return xxx_messageInfo_Options.Size(m)
}
func (m *Options) XXX_DiscardUnknown() {
	xxx_messageInfo_Options.DiscardUnknown(m)
}

var xxx_messageInfo_Options proto.InternalMessageInfo

const Default_Options_ReEvalSec int32 = 10
const Default_Options_RuntimeconfigName string = "lame-duck-targets"
const Default_Options_ExpirationSec int32 = 300
const Default_Options_RdsServerAddr string = "localhost:9314"

func (m *Options) GetReEvalSec() int32 {
	if m != nil && m.ReEvalSec != nil {
		return *m.ReEvalSec
	}
	return Default_Options_ReEvalSec
}

func (m *Options) GetRuntimeconfigProject() string {
	if m != nil && m.RuntimeconfigProject != nil {
		return *m.RuntimeconfigProject
	}
	return ""
}

func (m *Options) GetRuntimeconfigName() string {
	if m != nil && m.RuntimeconfigName != nil {
		return *m.RuntimeconfigName
	}
	return Default_Options_RuntimeconfigName
}

func (m *Options) GetExpirationSec() int32 {
	if m != nil && m.ExpirationSec != nil {
		return *m.ExpirationSec
	}
	return Default_Options_ExpirationSec
}

func (m *Options) GetUseRds() bool {
	if m != nil && m.UseRds != nil {
		return *m.UseRds
	}
	return false
}

func (m *Options) GetRdsServerAddr() string {
	if m != nil && m.RdsServerAddr != nil {
		return *m.RdsServerAddr
	}
	return Default_Options_RdsServerAddr
}

func init() {
	proto.RegisterType((*Options)(nil), "cloudprober.targets.lameduck.Options")
}

func init() {
	proto.RegisterFile("github.com/yext/cloudprober/targets/lameduck/proto/config.proto", fileDescriptor_config_0b9e4b76d3ac140e)
}

var fileDescriptor_config_0b9e4b76d3ac140e = []byte{
	// 289 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x54, 0xce, 0xc1, 0x4f, 0xc2, 0x30,
	0x14, 0xc7, 0xf1, 0x0c, 0x04, 0xa4, 0x06, 0x0c, 0x8d, 0xc6, 0x1d, 0x3c, 0x10, 0x4e, 0xc4, 0x84,
	0x0d, 0x82, 0x31, 0x91, 0x93, 0x1c, 0xbc, 0xaa, 0x29, 0x7f, 0x40, 0x53, 0xda, 0xe7, 0x98, 0x76,
	0x7b, 0xcb, 0x6b, 0x4b, 0xfc, 0x77, 0xfc, 0x4f, 0xcd, 0x06, 0x46, 0x39, 0x36, 0xbf, 0xf7, 0x4d,
	0x3f, 0x6c, 0x9d, 0xe5, 0x7e, 0x17, 0xb6, 0x89, 0xc6, 0x22, 0xcd, 0x10, 0x33, 0x0b, 0xa9, 0xb6,
	0x18, 0x4c, 0x45, 0xb8, 0x05, 0x4a, 0xbd, 0xa2, 0x0c, 0xbc, 0x4b, 0xad, 0x2a, 0xc0, 0x04, 0xfd,
	0x99, 0x56, 0x84, 0x1e, 0x53, 0x8d, 0xe5, 0x7b, 0x9e, 0x25, 0xcd, 0x83, 0xdf, 0xfe, 0x0b, 0x92,
	0x63, 0x90, 0xfc, 0x06, 0x93, 0xef, 0x16, 0xeb, 0xbd, 0x56, 0x3e, 0xc7, 0xd2, 0xf1, 0x09, 0xbb,
	0x20, 0x90, 0xb0, 0x57, 0x56, 0x3a, 0xd0, 0x71, 0x34, 0x8e, 0xa6, 0x9d, 0x55, 0x6b, 0x31, 0x17,
	0x7d, 0x82, 0xe7, 0xbd, 0xb2, 0x1b, 0xd0, 0x7c, 0xc9, 0xae, 0x29, 0x94, 0x3e, 0x2f, 0xe0, 0xf0,
	0x89, 0xac, 0x08, 0x3f, 0x40, 0xfb, 0xb8, 0x35, 0x8e, 0xa6, 0x7d, 0x71, 0x75, 0x32, 0xbe, 0x1d,
	0x36, 0xfe, 0xc4, 0xf8, 0x69, 0x54, 0xaa, 0x02, 0xe2, 0x76, 0x5d, 0xac, 0x46, 0x35, 0x65, 0x56,
	0x5b, 0x66, 0x47, 0x9c, 0x18, 0x9d, 0x1c, 0xbf, 0xa8, 0x02, 0xf8, 0x1d, 0x1b, 0xc2, 0x57, 0x95,
	0x93, 0xaa, 0xa5, 0x8d, 0xee, 0xac, 0xd1, 0xb5, 0x97, 0xf3, 0xb9, 0x18, 0xfc, 0x4d, 0x35, 0xf1,
	0x86, 0xf5, 0x82, 0x03, 0x49, 0xc6, 0xc5, 0x9d, 0x71, 0x34, 0x3d, 0x17, 0xdd, 0xe0, 0x40, 0x18,
	0xc7, 0x1f, 0xd8, 0x25, 0x19, 0x27, 0x1d, 0xd0, 0x1e, 0x48, 0x2a, 0x63, 0x28, 0xee, 0x36, 0x86,
	0xa1, 0x45, 0xad, 0xec, 0x0e, 0x9d, 0x5f, 0x3d, 0x2e, 0x17, 0xf7, 0x62, 0x40, 0xc6, 0x6d, 0x9a,
	0xab, 0xb5, 0x31, 0xf4, 0x13, 0x00, 0x00, 0xff, 0xff, 0xc7, 0x82, 0xb9, 0x23, 0x85, 0x01, 0x00,
	0x00,
}
