// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: github.com/yext/cloudprober/metrics/proto/dist.proto

package cloudprober_metrics

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

// Dist defines a Distribution data type.
type Dist struct {
	// Types that are valid to be assigned to Buckets:
	//	*Dist_ExplicitBuckets
	//	*Dist_ExponentialBuckets
	Buckets              isDist_Buckets `protobuf_oneof:"buckets"`
	XXX_NoUnkeyedLiteral struct{}       `json:"-"`
	XXX_unrecognized     []byte         `json:"-"`
	XXX_sizecache        int32          `json:"-"`
}

func (m *Dist) Reset()         { *m = Dist{} }
func (m *Dist) String() string { return proto.CompactTextString(m) }
func (*Dist) ProtoMessage()    {}
func (*Dist) Descriptor() ([]byte, []int) {
	return fileDescriptor_dist_9aa0e267cb2a7c48, []int{0}
}
func (m *Dist) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Dist.Unmarshal(m, b)
}
func (m *Dist) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Dist.Marshal(b, m, deterministic)
}
func (dst *Dist) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Dist.Merge(dst, src)
}
func (m *Dist) XXX_Size() int {
	return xxx_messageInfo_Dist.Size(m)
}
func (m *Dist) XXX_DiscardUnknown() {
	xxx_messageInfo_Dist.DiscardUnknown(m)
}

var xxx_messageInfo_Dist proto.InternalMessageInfo

type isDist_Buckets interface {
	isDist_Buckets()
}

type Dist_ExplicitBuckets struct {
	ExplicitBuckets string `protobuf:"bytes,1,opt,name=explicit_buckets,json=explicitBuckets,oneof"`
}
type Dist_ExponentialBuckets struct {
	ExponentialBuckets *ExponentialBuckets `protobuf:"bytes,2,opt,name=exponential_buckets,json=exponentialBuckets,oneof"`
}

func (*Dist_ExplicitBuckets) isDist_Buckets()    {}
func (*Dist_ExponentialBuckets) isDist_Buckets() {}

func (m *Dist) GetBuckets() isDist_Buckets {
	if m != nil {
		return m.Buckets
	}
	return nil
}

func (m *Dist) GetExplicitBuckets() string {
	if x, ok := m.GetBuckets().(*Dist_ExplicitBuckets); ok {
		return x.ExplicitBuckets
	}
	return ""
}

func (m *Dist) GetExponentialBuckets() *ExponentialBuckets {
	if x, ok := m.GetBuckets().(*Dist_ExponentialBuckets); ok {
		return x.ExponentialBuckets
	}
	return nil
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*Dist) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _Dist_OneofMarshaler, _Dist_OneofUnmarshaler, _Dist_OneofSizer, []interface{}{
		(*Dist_ExplicitBuckets)(nil),
		(*Dist_ExponentialBuckets)(nil),
	}
}

func _Dist_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*Dist)
	// buckets
	switch x := m.Buckets.(type) {
	case *Dist_ExplicitBuckets:
		_ = b.EncodeVarint(1<<3 | proto.WireBytes)
		_ = b.EncodeStringBytes(x.ExplicitBuckets)
	case *Dist_ExponentialBuckets:
		_ = b.EncodeVarint(2<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.ExponentialBuckets); err != nil {
			return err
		}
	case nil:
	default:
		return fmt.Errorf("Dist.Buckets has unexpected type %T", x)
	}
	return nil
}

func _Dist_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*Dist)
	switch tag {
	case 1: // buckets.explicit_buckets
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeStringBytes()
		m.Buckets = &Dist_ExplicitBuckets{x}
		return true, err
	case 2: // buckets.exponential_buckets
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(ExponentialBuckets)
		err := b.DecodeMessage(msg)
		m.Buckets = &Dist_ExponentialBuckets{msg}
		return true, err
	default:
		return false, nil
	}
}

func _Dist_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*Dist)
	// buckets
	switch x := m.Buckets.(type) {
	case *Dist_ExplicitBuckets:
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(len(x.ExplicitBuckets)))
		n += len(x.ExplicitBuckets)
	case *Dist_ExponentialBuckets:
		s := proto.Size(x.ExponentialBuckets)
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(s))
		n += s
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

// ExponentialBucket defines a set of num_buckets+2 buckets:
//   bucket[0] covers (−Inf, 0)
//   bucket[1] covers [0, scale_factor)
//   bucket[2] covers [scale_factor, scale_factor*base)
//   ...
//   bucket[i] covers [scale_factor*base^(i−2), scale_factor*base^(i−1))
//   ...
//   bucket[num_buckets+1] covers [scale_factor*base^(num_buckets−1), +Inf)
// NB: Base must be at least 1.01.
type ExponentialBuckets struct {
	ScaleFactor          *float32 `protobuf:"fixed32,1,opt,name=scale_factor,json=scaleFactor,def=1" json:"scale_factor,omitempty"`
	Base                 *float32 `protobuf:"fixed32,2,opt,name=base,def=2" json:"base,omitempty"`
	NumBuckets           *uint32  `protobuf:"varint,3,opt,name=num_buckets,json=numBuckets,def=20" json:"num_buckets,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ExponentialBuckets) Reset()         { *m = ExponentialBuckets{} }
func (m *ExponentialBuckets) String() string { return proto.CompactTextString(m) }
func (*ExponentialBuckets) ProtoMessage()    {}
func (*ExponentialBuckets) Descriptor() ([]byte, []int) {
	return fileDescriptor_dist_9aa0e267cb2a7c48, []int{1}
}
func (m *ExponentialBuckets) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ExponentialBuckets.Unmarshal(m, b)
}
func (m *ExponentialBuckets) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ExponentialBuckets.Marshal(b, m, deterministic)
}
func (dst *ExponentialBuckets) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ExponentialBuckets.Merge(dst, src)
}
func (m *ExponentialBuckets) XXX_Size() int {
	return xxx_messageInfo_ExponentialBuckets.Size(m)
}
func (m *ExponentialBuckets) XXX_DiscardUnknown() {
	xxx_messageInfo_ExponentialBuckets.DiscardUnknown(m)
}

var xxx_messageInfo_ExponentialBuckets proto.InternalMessageInfo

const Default_ExponentialBuckets_ScaleFactor float32 = 1
const Default_ExponentialBuckets_Base float32 = 2
const Default_ExponentialBuckets_NumBuckets uint32 = 20

func (m *ExponentialBuckets) GetScaleFactor() float32 {
	if m != nil && m.ScaleFactor != nil {
		return *m.ScaleFactor
	}
	return Default_ExponentialBuckets_ScaleFactor
}

func (m *ExponentialBuckets) GetBase() float32 {
	if m != nil && m.Base != nil {
		return *m.Base
	}
	return Default_ExponentialBuckets_Base
}

func (m *ExponentialBuckets) GetNumBuckets() uint32 {
	if m != nil && m.NumBuckets != nil {
		return *m.NumBuckets
	}
	return Default_ExponentialBuckets_NumBuckets
}

func init() {
	proto.RegisterType((*Dist)(nil), "cloudprober.metrics.Dist")
	proto.RegisterType((*ExponentialBuckets)(nil), "cloudprober.metrics.ExponentialBuckets")
}

func init() {
	proto.RegisterFile("github.com/yext/cloudprober/metrics/proto/dist.proto", fileDescriptor_dist_9aa0e267cb2a7c48)
}

var fileDescriptor_dist_9aa0e267cb2a7c48 = []byte{
	// 243 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x6c, 0x8e, 0x41, 0x4b, 0xc4, 0x30,
	0x14, 0x84, 0x37, 0x75, 0x41, 0xf6, 0x55, 0x51, 0xb2, 0x08, 0x1e, 0xcb, 0x2a, 0x58, 0x10, 0x12,
	0x2d, 0x9e, 0x7a, 0x5c, 0x54, 0xf6, 0x9c, 0xa3, 0x97, 0xa5, 0xcd, 0x3e, 0x35, 0xd8, 0x36, 0x25,
	0x79, 0x91, 0xfa, 0x57, 0xfc, 0xb5, 0x42, 0xac, 0xab, 0x50, 0x6f, 0xc9, 0xcc, 0xf7, 0x66, 0x06,
	0xee, 0x5e, 0x0c, 0xbd, 0x86, 0x5a, 0x68, 0xdb, 0xca, 0x0f, 0x1c, 0x48, 0xea, 0xc6, 0x86, 0x5d,
	0xef, 0x6c, 0x8d, 0x4e, 0xb6, 0x48, 0xce, 0x68, 0x2f, 0x7b, 0x67, 0xc9, 0xca, 0x9d, 0xf1, 0x24,
	0xe2, 0x93, 0x2f, 0xff, 0x50, 0x62, 0xa4, 0x56, 0x9f, 0x0c, 0xe6, 0xf7, 0xc6, 0x13, 0xbf, 0x86,
	0x53, 0x1c, 0xfa, 0xc6, 0x68, 0x43, 0xdb, 0x3a, 0xe8, 0x37, 0x24, 0x7f, 0xce, 0x32, 0x96, 0x2f,
	0x36, 0x33, 0x75, 0xf2, 0xe3, 0xac, 0xbf, 0x0d, 0xfe, 0x04, 0x4b, 0x1c, 0x7a, 0xdb, 0x61, 0x47,
	0xa6, 0x6a, 0xf6, 0x7c, 0x92, 0xb1, 0x3c, 0x2d, 0xae, 0xc4, 0x3f, 0x45, 0xe2, 0xe1, 0x97, 0x1f,
	0x53, 0x36, 0x33, 0xc5, 0x71, 0xa2, 0xae, 0x17, 0x70, 0x38, 0xe6, 0xad, 0xde, 0x81, 0x4f, 0xcf,
	0xf8, 0x25, 0x1c, 0x79, 0x5d, 0x35, 0xb8, 0x7d, 0xae, 0x34, 0x59, 0x17, 0x57, 0x26, 0x25, 0xbb,
	0x55, 0x69, 0x94, 0x1f, 0xa3, 0xca, 0xcf, 0x60, 0x5e, 0x57, 0x1e, 0xe3, 0xa6, 0xa4, 0x64, 0x85,
	0x8a, 0x5f, 0x7e, 0x01, 0x69, 0x17, 0xda, 0xfd, 0xe2, 0x83, 0x8c, 0xe5, 0xc7, 0x65, 0x52, 0xdc,
	0x28, 0xe8, 0x42, 0x3b, 0x36, 0x7c, 0x05, 0x00, 0x00, 0xff, 0xff, 0x33, 0x3f, 0xaf, 0x4e, 0x60,
	0x01, 0x00, 0x00,
}
