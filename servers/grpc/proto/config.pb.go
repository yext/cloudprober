// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: github.com/yext/cloudprober/servers/grpc/proto/config.proto

package cloudprober_servers_grpc

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

type ServerConf struct {
	Port *int32 `protobuf:"varint,1,opt,name=port,def=3142" json:"port,omitempty"`
	// Enables gRPC reflection for publicly visible services, allowing grpc_cli to
	// work. See https://grpc.io/grpc/core/md_doc_server_reflection_tutorial.html.
	EnableReflection *bool `protobuf:"varint,2,opt,name=enable_reflection,json=enableReflection,def=0" json:"enable_reflection,omitempty"`
	// If use_dedicated_server is set to true, then create a new gRPC server
	// to handle probes. Otherwise, attempt to reuse gRPC server from runconfig
	// if that was set.
	UseDedicatedServer   *bool    `protobuf:"varint,3,opt,name=use_dedicated_server,json=useDedicatedServer,def=1" json:"use_dedicated_server,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ServerConf) Reset()         { *m = ServerConf{} }
func (m *ServerConf) String() string { return proto.CompactTextString(m) }
func (*ServerConf) ProtoMessage()    {}
func (*ServerConf) Descriptor() ([]byte, []int) {
	return fileDescriptor_config_f50537a793ef81d4, []int{0}
}
func (m *ServerConf) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ServerConf.Unmarshal(m, b)
}
func (m *ServerConf) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ServerConf.Marshal(b, m, deterministic)
}
func (dst *ServerConf) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ServerConf.Merge(dst, src)
}
func (m *ServerConf) XXX_Size() int {
	return xxx_messageInfo_ServerConf.Size(m)
}
func (m *ServerConf) XXX_DiscardUnknown() {
	xxx_messageInfo_ServerConf.DiscardUnknown(m)
}

var xxx_messageInfo_ServerConf proto.InternalMessageInfo

const Default_ServerConf_Port int32 = 3142
const Default_ServerConf_EnableReflection bool = false
const Default_ServerConf_UseDedicatedServer bool = true

func (m *ServerConf) GetPort() int32 {
	if m != nil && m.Port != nil {
		return *m.Port
	}
	return Default_ServerConf_Port
}

func (m *ServerConf) GetEnableReflection() bool {
	if m != nil && m.EnableReflection != nil {
		return *m.EnableReflection
	}
	return Default_ServerConf_EnableReflection
}

func (m *ServerConf) GetUseDedicatedServer() bool {
	if m != nil && m.UseDedicatedServer != nil {
		return *m.UseDedicatedServer
	}
	return Default_ServerConf_UseDedicatedServer
}

func init() {
	proto.RegisterType((*ServerConf)(nil), "cloudprober.servers.grpc.ServerConf")
}

func init() {
	proto.RegisterFile("github.com/yext/cloudprober/servers/grpc/proto/config.proto", fileDescriptor_config_f50537a793ef81d4)
}

var fileDescriptor_config_f50537a793ef81d4 = []byte{
	// 200 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x4c, 0xce, 0xb1, 0x4e, 0x04, 0x21,
	0x10, 0x06, 0xe0, 0xa0, 0x7b, 0x89, 0xa1, 0x52, 0x62, 0x41, 0x79, 0xb1, 0xba, 0x0a, 0xe2, 0x69,
	0x2c, 0xd6, 0x52, 0x9f, 0x00, 0x1f, 0x60, 0xb3, 0x0b, 0xc3, 0x4a, 0x82, 0x0c, 0x19, 0xc0, 0xe8,
	0x6b, 0xf8, 0xc4, 0x46, 0x56, 0xcd, 0x95, 0xf3, 0xff, 0xdf, 0x64, 0x86, 0x3f, 0xae, 0xa1, 0xbe,
	0xb6, 0x45, 0x59, 0x7c, 0xd3, 0x9f, 0xf0, 0x51, 0xb5, 0x8d, 0xd8, 0x5c, 0x26, 0x5c, 0x80, 0x74,
	0x01, 0x7a, 0x07, 0x2a, 0x7a, 0xa5, 0x6c, 0x75, 0x26, 0xac, 0xa8, 0x2d, 0x26, 0x1f, 0x56, 0xd5,
	0x07, 0x21, 0x4f, 0xb0, 0xfa, 0xc5, 0xea, 0x07, 0xdf, 0x7c, 0x31, 0xce, 0x5f, 0x7a, 0xf0, 0x84,
	0xc9, 0x0b, 0xc9, 0x87, 0x8c, 0x54, 0x25, 0xdb, 0xb3, 0xc3, 0x6e, 0x1c, 0xee, 0x6e, 0xef, 0x8f,
	0xa6, 0x27, 0xe2, 0xc8, 0xaf, 0x20, 0xcd, 0x4b, 0x84, 0x89, 0xc0, 0x47, 0xb0, 0x35, 0x60, 0x92,
	0x67, 0x7b, 0x76, 0xb8, 0x18, 0x77, 0x7e, 0x8e, 0x05, 0xcc, 0xe5, 0xd6, 0x9b, 0xff, 0x5a, 0x3c,
	0xf0, 0xeb, 0x56, 0x60, 0x72, 0xe0, 0x82, 0x9d, 0x2b, 0xb8, 0x69, 0x3b, 0x2d, 0xcf, 0xfb, 0xda,
	0x50, 0xa9, 0x81, 0x11, 0xad, 0xc0, 0xf3, 0x1f, 0xd8, 0x3e, 0xf9, 0x0e, 0x00, 0x00, 0xff, 0xff,
	0x29, 0xea, 0x37, 0x6a, 0xec, 0x00, 0x00, 0x00,
}
