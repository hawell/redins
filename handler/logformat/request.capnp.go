// Code generated by capnpc-go. DO NOT EDIT.

package logformat

import (
	capnp "zombiezen.com/go/capnproto2"
	text "zombiezen.com/go/capnproto2/encoding/text"
	schemas "zombiezen.com/go/capnproto2/schemas"
)

type RequestLog struct{ capnp.Struct }

// RequestLog_TypeID is the unique identifier for the type RequestLog.
const RequestLog_TypeID = 0xc3dd579d38a573e0

func NewRequestLog(s *capnp.Segment) (RequestLog, error) {
	st, err := capnp.NewStruct(s, capnp.ObjectSize{DataSize: 16, PointerCount: 5})
	return RequestLog{st}, err
}

func NewRootRequestLog(s *capnp.Segment) (RequestLog, error) {
	st, err := capnp.NewRootStruct(s, capnp.ObjectSize{DataSize: 16, PointerCount: 5})
	return RequestLog{st}, err
}

func ReadRootRequestLog(msg *capnp.Message) (RequestLog, error) {
	root, err := msg.RootPtr()
	return RequestLog{root.Struct()}, err
}

func (s RequestLog) String() string {
	str, _ := text.Marshal(0xc3dd579d38a573e0, s.Struct)
	return str
}

func (s RequestLog) Timestamp() uint64 {
	return s.Struct.Uint64(0)
}

func (s RequestLog) SetTimestamp(v uint64) {
	s.Struct.SetUint64(0, v)
}

func (s RequestLog) Uuid() (string, error) {
	p, err := s.Struct.Ptr(0)
	return p.Text(), err
}

func (s RequestLog) HasUuid() bool {
	p, err := s.Struct.Ptr(0)
	return p.IsValid() || err != nil
}

func (s RequestLog) UuidBytes() ([]byte, error) {
	p, err := s.Struct.Ptr(0)
	return p.TextBytes(), err
}

func (s RequestLog) SetUuid(v string) error {
	return s.Struct.SetText(0, v)
}

func (s RequestLog) Record() (string, error) {
	p, err := s.Struct.Ptr(1)
	return p.Text(), err
}

func (s RequestLog) HasRecord() bool {
	p, err := s.Struct.Ptr(1)
	return p.IsValid() || err != nil
}

func (s RequestLog) RecordBytes() ([]byte, error) {
	p, err := s.Struct.Ptr(1)
	return p.TextBytes(), err
}

func (s RequestLog) SetRecord(v string) error {
	return s.Struct.SetText(1, v)
}

func (s RequestLog) Type() (string, error) {
	p, err := s.Struct.Ptr(2)
	return p.Text(), err
}

func (s RequestLog) HasType() bool {
	p, err := s.Struct.Ptr(2)
	return p.IsValid() || err != nil
}

func (s RequestLog) TypeBytes() ([]byte, error) {
	p, err := s.Struct.Ptr(2)
	return p.TextBytes(), err
}

func (s RequestLog) SetType(v string) error {
	return s.Struct.SetText(2, v)
}

func (s RequestLog) Ip() (string, error) {
	p, err := s.Struct.Ptr(3)
	return p.Text(), err
}

func (s RequestLog) HasIp() bool {
	p, err := s.Struct.Ptr(3)
	return p.IsValid() || err != nil
}

func (s RequestLog) IpBytes() ([]byte, error) {
	p, err := s.Struct.Ptr(3)
	return p.TextBytes(), err
}

func (s RequestLog) SetIp(v string) error {
	return s.Struct.SetText(3, v)
}

func (s RequestLog) Country() (string, error) {
	p, err := s.Struct.Ptr(4)
	return p.Text(), err
}

func (s RequestLog) HasCountry() bool {
	p, err := s.Struct.Ptr(4)
	return p.IsValid() || err != nil
}

func (s RequestLog) CountryBytes() ([]byte, error) {
	p, err := s.Struct.Ptr(4)
	return p.TextBytes(), err
}

func (s RequestLog) SetCountry(v string) error {
	return s.Struct.SetText(4, v)
}

func (s RequestLog) Asn() uint32 {
	return s.Struct.Uint32(8)
}

func (s RequestLog) SetAsn(v uint32) {
	s.Struct.SetUint32(8, v)
}

func (s RequestLog) Responsecode() uint16 {
	return s.Struct.Uint16(12)
}

func (s RequestLog) SetResponsecode(v uint16) {
	s.Struct.SetUint16(12, v)
}

func (s RequestLog) Processtime() uint16 {
	return s.Struct.Uint16(14)
}

func (s RequestLog) SetProcesstime(v uint16) {
	s.Struct.SetUint16(14, v)
}

// RequestLog_List is a list of RequestLog.
type RequestLog_List struct{ capnp.List }

// NewRequestLog creates a new list of RequestLog.
func NewRequestLog_List(s *capnp.Segment, sz int32) (RequestLog_List, error) {
	l, err := capnp.NewCompositeList(s, capnp.ObjectSize{DataSize: 16, PointerCount: 5}, sz)
	return RequestLog_List{l}, err
}

func (s RequestLog_List) At(i int) RequestLog { return RequestLog{s.List.Struct(i)} }

func (s RequestLog_List) Set(i int, v RequestLog) error { return s.List.SetStruct(i, v.Struct) }

func (s RequestLog_List) String() string {
	str, _ := text.MarshalList(0xc3dd579d38a573e0, s.List)
	return str
}

// RequestLog_Promise is a wrapper for a RequestLog promised by a client call.
type RequestLog_Promise struct{ *capnp.Pipeline }

func (p RequestLog_Promise) Struct() (RequestLog, error) {
	s, err := p.Pipeline.Struct()
	return RequestLog{s}, err
}

const schema_8d8d9fbdbf80710e = "x\xda<\xca\xb1\xca\xd3P\x00\xc5\xf1s\xeeMrS" +
	"\x88mC\xae N\"N\x82B7\xe9\xa28;x" +
	"\x93\xc1\xb9\xa6\x17\x89\xd0$\xcdM\x86N\xfa\x02}\x04" +
	"q\xf21\xa4\x83\xb8(\x0e>\x80\xe0\x03(8(T" +
	"\xa8D.\x1f\xedv\xfe?\xce\xfc\xf3#\xb1\x08\x0f\x04" +
	"\x8c\x0e\xa3\xf1\xbb{\xf7\xe0\xcd\xb3o\x1f`\xa6\x14\xe3" +
	"t\xfb\xfa\xf0\xfe\xed~\x8f0T@\xfa\xf1S\xfaU" +
	"\x01\x8b/#qo\xec\xecv\xb0\xae\xbf/\xcaU[" +
	"\xb7\xcb\xfc*\x9f4/\x80\xa7\xa4\xb9#\x03  \x90" +
	"\xfe\xcc\x01\xf3C\xd2\x1c\x05IMo\x7f\xee\x02\xe6\x97" +
	"\xa49\x09\xa6\x82\x9a\x02H\xff.\x01\xf3[2\xa7`" +
	"*\x85\xa6\x04\xd2\x7f\xfey\x94,\x02\xaf\x81\xd4\x0c\x80" +
	"\x8c\xbc\x09\x98\x93d\x11{\x0e\x03\xcd\x10\xc8B>\x06" +
	"rJ\x16\x89\xe7HhF@6\xe1m\xa0\x08\xbc\xcf" +
	"\xbd\xabHS\x01\xd95\xbe\x04\x8a\xc4\xfb\x0d\xef\xb1\xd2" +
	"\x8c\x81\xec:\x9f\x03\x85\xf6~\x8b\x82c_m\xac\xeb" +
	"W\x1b\xb0\xe5\x04\x82\x13p6\x0c\xd5\x9a\x09\x04\x13\xf0" +
	"ag\xcb\xa6\xbb\xe4\xac\xdf\xb5\xf6\x1c\xb2j\xcf\xf3U" +
	"\xd9\x0cu\xdf\xed\xce\xadV\xaef\x0c\xc1\x18\x1c;\xeb" +
	"\xda\xa6v\x16\xb3\xb2Y[*\x08*pl\xbb\xa6\xb4" +
	"\xce\xf5P\xd5\xe6\xa2\xff\x03\x00\x00\xff\xffS&Q;"

func init() {
	schemas.Register(schema_8d8d9fbdbf80710e,
		0xc3dd579d38a573e0)
}
