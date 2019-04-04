// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: github.com/yext/cloudprober/targets/rds/client/proto/config.proto

package cloudprober_targets_rds

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import proto1 "github.com/yext/cloudprober/targets/rds/proto"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

// ClientConf represents resource discovery service (RDS) based targets.
type ClientConf struct {
	ServerAddr *string                      `protobuf:"bytes,1,opt,name=server_addr,json=serverAddr,def=localhost:9314" json:"server_addr,omitempty"`
	Request    *proto1.ListResourcesRequest `protobuf:"bytes,2,req,name=request" json:"request,omitempty"`
	// How often targets should be evaluated. Any number less than or equal to 0
	// will result in no target caching (targets will be reevaluated on demand).
	// Note that individual target types may have their own caches implemented
	// (specifically GCE instances/forwarding rules). This does not impact those
	// caches.
	ReEvalSec            *int32   `protobuf:"varint,3,opt,name=re_eval_sec,json=reEvalSec,def=30" json:"re_eval_sec,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ClientConf) Reset()         { *m = ClientConf{} }
func (m *ClientConf) String() string { return proto.CompactTextString(m) }
func (*ClientConf) ProtoMessage()    {}
func (*ClientConf) Descriptor() ([]byte, []int) {
	return fileDescriptor_config_7d046d340eb138f9, []int{0}
}
func (m *ClientConf) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ClientConf.Unmarshal(m, b)
}
func (m *ClientConf) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ClientConf.Marshal(b, m, deterministic)
}
func (dst *ClientConf) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ClientConf.Merge(dst, src)
}
func (m *ClientConf) XXX_Size() int {
	return xxx_messageInfo_ClientConf.Size(m)
}
func (m *ClientConf) XXX_DiscardUnknown() {
	xxx_messageInfo_ClientConf.DiscardUnknown(m)
}

var xxx_messageInfo_ClientConf proto.InternalMessageInfo

const Default_ClientConf_ServerAddr string = "localhost:9314"
const Default_ClientConf_ReEvalSec int32 = 30

func (m *ClientConf) GetServerAddr() string {
	if m != nil && m.ServerAddr != nil {
		return *m.ServerAddr
	}
	return Default_ClientConf_ServerAddr
}

func (m *ClientConf) GetRequest() *proto1.ListResourcesRequest {
	if m != nil {
		return m.Request
	}
	return nil
}

func (m *ClientConf) GetReEvalSec() int32 {
	if m != nil && m.ReEvalSec != nil {
		return *m.ReEvalSec
	}
	return Default_ClientConf_ReEvalSec
}

func init() {
	proto.RegisterType((*ClientConf)(nil), "cloudprober.targets.rds.ClientConf")
}

func init() {
	proto.RegisterFile("github.com/yext/cloudprober/targets/rds/client/proto/config.proto", fileDescriptor_config_7d046d340eb138f9)
}

var fileDescriptor_config_7d046d340eb138f9 = []byte{
	// 234 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0xce, 0xb1, 0x4a, 0xc4, 0x40,
	0x10, 0x80, 0x61, 0x12, 0x11, 0xb9, 0x0d, 0x58, 0xa4, 0x31, 0x58, 0x85, 0xab, 0xd2, 0xb8, 0xab,
	0x9e, 0x20, 0xa6, 0x3b, 0x0e, 0xb1, 0xb1, 0x5a, 0x1f, 0x20, 0xec, 0xed, 0xce, 0xe5, 0x02, 0x6b,
	0xe6, 0x9c, 0x99, 0x04, 0x7d, 0x25, 0x9f, 0x52, 0xb8, 0x55, 0xb0, 0x11, 0x2c, 0x07, 0xe6, 0xfb,
	0x67, 0xd4, 0xba, 0x1f, 0x64, 0x3f, 0x6d, 0xb5, 0xc7, 0x57, 0xf3, 0x01, 0xef, 0x62, 0x7c, 0xc4,
	0x29, 0x1c, 0x08, 0xb7, 0x40, 0x46, 0x1c, 0xf5, 0x20, 0x6c, 0x28, 0xb0, 0xf1, 0x71, 0x80, 0x51,
	0xcc, 0x81, 0x50, 0xd0, 0x78, 0x1c, 0x77, 0x43, 0xaf, 0x8f, 0x43, 0x79, 0xf1, 0x8b, 0xe8, 0x6f,
	0xa2, 0x29, 0xf0, 0xe5, 0xfd, 0x7f, 0xdb, 0x29, 0x4a, 0x81, 0x53, 0x71, 0xf9, 0x99, 0x29, 0xb5,
	0x39, 0xde, 0xdb, 0xe0, 0xb8, 0x2b, 0x8d, 0x2a, 0x18, 0x68, 0x06, 0xea, 0x5c, 0x08, 0x54, 0x65,
	0x75, 0xd6, 0x2c, 0xda, 0xf3, 0x88, 0xde, 0xc5, 0x3d, 0xb2, 0xb4, 0x0f, 0xab, 0x9b, 0x3b, 0xab,
	0xd2, 0xca, 0x3a, 0x04, 0x2a, 0x9f, 0xd4, 0x19, 0xc1, 0xdb, 0x04, 0x2c, 0x55, 0x5e, 0xe7, 0x4d,
	0x71, 0x7b, 0xa5, 0xff, 0xf8, 0x51, 0x3f, 0x0f, 0x2c, 0x16, 0x18, 0x27, 0xf2, 0xc0, 0x36, 0x21,
	0xfb, 0xa3, 0xcb, 0xa5, 0x2a, 0x08, 0x3a, 0x98, 0x5d, 0xec, 0x18, 0x7c, 0x75, 0x52, 0x67, 0xcd,
	0x69, 0x9b, 0xaf, 0xae, 0xed, 0x82, 0xe0, 0x71, 0x76, 0xf1, 0x05, 0xfc, 0x57, 0x00, 0x00, 0x00,
	0xff, 0xff, 0x9a, 0xe5, 0x83, 0xb2, 0x42, 0x01, 0x00, 0x00,
}
