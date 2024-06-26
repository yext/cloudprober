// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: github.com/yext/cloudprober/validators/proto/config.proto

package cloudprober_validators

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import proto1 "github.com/yext/cloudprober/validators/http/proto"
import proto2 "github.com/yext/cloudprober/validators/integrity/proto"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

type Validator struct {
	Name *string `protobuf:"bytes,1,req,name=name" json:"name,omitempty"`
	// Types that are valid to be assigned to Type:
	//	*Validator_HttpValidator
	//	*Validator_IntegrityValidator
	//	*Validator_Regex
	Type                 isValidator_Type `protobuf_oneof:"type"`
	XXX_NoUnkeyedLiteral struct{}         `json:"-"`
	XXX_unrecognized     []byte           `json:"-"`
	XXX_sizecache        int32            `json:"-"`
}

func (m *Validator) Reset()         { *m = Validator{} }
func (m *Validator) String() string { return proto.CompactTextString(m) }
func (*Validator) ProtoMessage()    {}
func (*Validator) Descriptor() ([]byte, []int) {
	return fileDescriptor_config_27d198f12a9307c7, []int{0}
}
func (m *Validator) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Validator.Unmarshal(m, b)
}
func (m *Validator) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Validator.Marshal(b, m, deterministic)
}
func (dst *Validator) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Validator.Merge(dst, src)
}
func (m *Validator) XXX_Size() int {
	return xxx_messageInfo_Validator.Size(m)
}
func (m *Validator) XXX_DiscardUnknown() {
	xxx_messageInfo_Validator.DiscardUnknown(m)
}

var xxx_messageInfo_Validator proto.InternalMessageInfo

type isValidator_Type interface {
	isValidator_Type()
}

type Validator_HttpValidator struct {
	HttpValidator *proto1.Validator `protobuf:"bytes,2,opt,name=http_validator,json=httpValidator,oneof"`
}
type Validator_IntegrityValidator struct {
	IntegrityValidator *proto2.Validator `protobuf:"bytes,3,opt,name=integrity_validator,json=integrityValidator,oneof"`
}
type Validator_Regex struct {
	Regex string `protobuf:"bytes,4,opt,name=regex,oneof"`
}

func (*Validator_HttpValidator) isValidator_Type()      {}
func (*Validator_IntegrityValidator) isValidator_Type() {}
func (*Validator_Regex) isValidator_Type()              {}

func (m *Validator) GetType() isValidator_Type {
	if m != nil {
		return m.Type
	}
	return nil
}

func (m *Validator) GetName() string {
	if m != nil && m.Name != nil {
		return *m.Name
	}
	return ""
}

func (m *Validator) GetHttpValidator() *proto1.Validator {
	if x, ok := m.GetType().(*Validator_HttpValidator); ok {
		return x.HttpValidator
	}
	return nil
}

func (m *Validator) GetIntegrityValidator() *proto2.Validator {
	if x, ok := m.GetType().(*Validator_IntegrityValidator); ok {
		return x.IntegrityValidator
	}
	return nil
}

func (m *Validator) GetRegex() string {
	if x, ok := m.GetType().(*Validator_Regex); ok {
		return x.Regex
	}
	return ""
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*Validator) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _Validator_OneofMarshaler, _Validator_OneofUnmarshaler, _Validator_OneofSizer, []interface{}{
		(*Validator_HttpValidator)(nil),
		(*Validator_IntegrityValidator)(nil),
		(*Validator_Regex)(nil),
	}
}

func _Validator_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*Validator)
	// type
	switch x := m.Type.(type) {
	case *Validator_HttpValidator:
		_ = b.EncodeVarint(2<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.HttpValidator); err != nil {
			return err
		}
	case *Validator_IntegrityValidator:
		_ = b.EncodeVarint(3<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.IntegrityValidator); err != nil {
			return err
		}
	case *Validator_Regex:
		_ = b.EncodeVarint(4<<3 | proto.WireBytes)
		_ = b.EncodeStringBytes(x.Regex)
	case nil:
	default:
		return fmt.Errorf("Validator.Type has unexpected type %T", x)
	}
	return nil
}

func _Validator_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*Validator)
	switch tag {
	case 2: // type.http_validator
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(proto1.Validator)
		err := b.DecodeMessage(msg)
		m.Type = &Validator_HttpValidator{msg}
		return true, err
	case 3: // type.integrity_validator
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(proto2.Validator)
		err := b.DecodeMessage(msg)
		m.Type = &Validator_IntegrityValidator{msg}
		return true, err
	case 4: // type.regex
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeStringBytes()
		m.Type = &Validator_Regex{x}
		return true, err
	default:
		return false, nil
	}
}

func _Validator_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*Validator)
	// type
	switch x := m.Type.(type) {
	case *Validator_HttpValidator:
		s := proto.Size(x.HttpValidator)
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(s))
		n += s
	case *Validator_IntegrityValidator:
		s := proto.Size(x.IntegrityValidator)
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(s))
		n += s
	case *Validator_Regex:
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(len(x.Regex)))
		n += len(x.Regex)
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

func init() {
	proto.RegisterType((*Validator)(nil), "cloudprober.validators.Validator")
}

func init() {
	proto.RegisterFile("github.com/yext/cloudprober/validators/proto/config.proto", fileDescriptor_config_27d198f12a9307c7)
}

var fileDescriptor_config_27d198f12a9307c7 = []byte{
	// 223 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xb2, 0x4c, 0xcf, 0x2c, 0xc9,
	0x28, 0x4d, 0xd2, 0x4b, 0xce, 0xcf, 0xd5, 0xaf, 0x4c, 0xad, 0x28, 0xd1, 0x4f, 0xce, 0xc9, 0x2f,
	0x4d, 0x29, 0x28, 0xca, 0x4f, 0x4a, 0x2d, 0xd2, 0x2f, 0x4b, 0xcc, 0xc9, 0x4c, 0x49, 0x2c, 0xc9,
	0x2f, 0x2a, 0xd6, 0x2f, 0x28, 0xca, 0x2f, 0xc9, 0xd7, 0x4f, 0xce, 0xcf, 0x4b, 0xcb, 0x4c, 0xd7,
	0x03, 0x73, 0x84, 0xc4, 0x90, 0x94, 0xea, 0x21, 0x94, 0x4a, 0xd9, 0x11, 0x69, 0x64, 0x46, 0x49,
	0x49, 0x01, 0x16, 0x73, 0xa5, 0x9c, 0x89, 0xd4, 0x9f, 0x99, 0x57, 0x92, 0x9a, 0x5e, 0x94, 0x59,
	0x52, 0x89, 0xc5, 0x10, 0xa5, 0x0f, 0x8c, 0x5c, 0x9c, 0x61, 0x30, 0xb5, 0x42, 0x42, 0x5c, 0x2c,
	0x79, 0x89, 0xb9, 0xa9, 0x12, 0x8c, 0x0a, 0x4c, 0x1a, 0x9c, 0x41, 0x60, 0xb6, 0x90, 0x3f, 0x17,
	0x1f, 0xc8, 0x05, 0xf1, 0x70, 0x13, 0x25, 0x98, 0x14, 0x18, 0x35, 0xb8, 0x8d, 0xd4, 0xf4, 0xb0,
	0xfb, 0x4b, 0x0f, 0xa4, 0x5a, 0x0f, 0x6e, 0xa6, 0x07, 0x43, 0x10, 0x2f, 0x48, 0x04, 0x61, 0x49,
	0x1c, 0x97, 0x30, 0xdc, 0x49, 0x48, 0xa6, 0x32, 0x83, 0x4d, 0xd5, 0xc6, 0x65, 0x2a, 0x5c, 0x0b,
	0x8a, 0xd1, 0x42, 0x70, 0x61, 0x84, 0xf9, 0x62, 0x5c, 0xac, 0x45, 0xa9, 0xe9, 0xa9, 0x15, 0x12,
	0x2c, 0x0a, 0x8c, 0x1a, 0x9c, 0x1e, 0x0c, 0x41, 0x10, 0xae, 0x13, 0x1b, 0x17, 0x4b, 0x49, 0x65,
	0x41, 0x2a, 0x20, 0x00, 0x00, 0xff, 0xff, 0x87, 0xe2, 0xba, 0x1a, 0xcb, 0x01, 0x00, 0x00,
}
