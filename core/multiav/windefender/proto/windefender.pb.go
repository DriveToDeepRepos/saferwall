// Code generated by protoc-gen-go. DO NOT EDIT.
// source: multiav.windefender.proto

package windefender_api

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

// The scan file request message containing the file path to scan.
type ScanFileRequest struct {
	Filepath             string   `protobuf:"bytes,1,opt,name=filepath,proto3" json:"filepath,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ScanFileRequest) Reset()         { *m = ScanFileRequest{} }
func (m *ScanFileRequest) String() string { return proto.CompactTextString(m) }
func (*ScanFileRequest) ProtoMessage()    {}
func (*ScanFileRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_621cc4576e61590e, []int{0}
}

func (m *ScanFileRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ScanFileRequest.Unmarshal(m, b)
}
func (m *ScanFileRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ScanFileRequest.Marshal(b, m, deterministic)
}
func (m *ScanFileRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ScanFileRequest.Merge(m, src)
}
func (m *ScanFileRequest) XXX_Size() int {
	return xxx_messageInfo_ScanFileRequest.Size(m)
}
func (m *ScanFileRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_ScanFileRequest.DiscardUnknown(m)
}

var xxx_messageInfo_ScanFileRequest proto.InternalMessageInfo

func (m *ScanFileRequest) GetFilepath() string {
	if m != nil {
		return m.Filepath
	}
	return ""
}

// The scan response message containing detection results of the AntiVirus.
type ScanResponse struct {
	Output               string   `protobuf:"bytes,1,opt,name=output,proto3" json:"output,omitempty"`
	Infected             bool     `protobuf:"varint,2,opt,name=infected,proto3" json:"infected,omitempty"`
	Update               int64    `protobuf:"varint,3,opt,name=update,proto3" json:"update,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ScanResponse) Reset()         { *m = ScanResponse{} }
func (m *ScanResponse) String() string { return proto.CompactTextString(m) }
func (*ScanResponse) ProtoMessage()    {}
func (*ScanResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_621cc4576e61590e, []int{1}
}

func (m *ScanResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ScanResponse.Unmarshal(m, b)
}
func (m *ScanResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ScanResponse.Marshal(b, m, deterministic)
}
func (m *ScanResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ScanResponse.Merge(m, src)
}
func (m *ScanResponse) XXX_Size() int {
	return xxx_messageInfo_ScanResponse.Size(m)
}
func (m *ScanResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_ScanResponse.DiscardUnknown(m)
}

var xxx_messageInfo_ScanResponse proto.InternalMessageInfo

func (m *ScanResponse) GetOutput() string {
	if m != nil {
		return m.Output
	}
	return ""
}

func (m *ScanResponse) GetInfected() bool {
	if m != nil {
		return m.Infected
	}
	return false
}

func (m *ScanResponse) GetUpdate() int64 {
	if m != nil {
		return m.Update
	}
	return 0
}

// The version request message ask for version.
type VersionRequest struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *VersionRequest) Reset()         { *m = VersionRequest{} }
func (m *VersionRequest) String() string { return proto.CompactTextString(m) }
func (*VersionRequest) ProtoMessage()    {}
func (*VersionRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_621cc4576e61590e, []int{2}
}

func (m *VersionRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_VersionRequest.Unmarshal(m, b)
}
func (m *VersionRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_VersionRequest.Marshal(b, m, deterministic)
}
func (m *VersionRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VersionRequest.Merge(m, src)
}
func (m *VersionRequest) XXX_Size() int {
	return xxx_messageInfo_VersionRequest.Size(m)
}
func (m *VersionRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_VersionRequest.DiscardUnknown(m)
}

var xxx_messageInfo_VersionRequest proto.InternalMessageInfo

// The response message containing program/VPS version.
type VersionResponse struct {
	Version              string   `protobuf:"bytes,1,opt,name=version,proto3" json:"version,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *VersionResponse) Reset()         { *m = VersionResponse{} }
func (m *VersionResponse) String() string { return proto.CompactTextString(m) }
func (*VersionResponse) ProtoMessage()    {}
func (*VersionResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_621cc4576e61590e, []int{3}
}

func (m *VersionResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_VersionResponse.Unmarshal(m, b)
}
func (m *VersionResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_VersionResponse.Marshal(b, m, deterministic)
}
func (m *VersionResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_VersionResponse.Merge(m, src)
}
func (m *VersionResponse) XXX_Size() int {
	return xxx_messageInfo_VersionResponse.Size(m)
}
func (m *VersionResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_VersionResponse.DiscardUnknown(m)
}

var xxx_messageInfo_VersionResponse proto.InternalMessageInfo

func (m *VersionResponse) GetVersion() string {
	if m != nil {
		return m.Version
	}
	return ""
}

func init() {
	proto.RegisterType((*ScanFileRequest)(nil), "windefender.api.ScanFileRequest")
	proto.RegisterType((*ScanResponse)(nil), "windefender.api.ScanResponse")
	proto.RegisterType((*VersionRequest)(nil), "windefender.api.VersionRequest")
	proto.RegisterType((*VersionResponse)(nil), "windefender.api.VersionResponse")
}

func init() { proto.RegisterFile("multiav.windefender.proto", fileDescriptor_621cc4576e61590e) }

var fileDescriptor_621cc4576e61590e = []byte{
	// 250 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x74, 0x91, 0x41, 0x4b, 0xc4, 0x30,
	0x10, 0x85, 0x8d, 0x0b, 0x6b, 0x1d, 0xc4, 0x4a, 0x0e, 0x52, 0x0b, 0x62, 0xc8, 0xa9, 0x20, 0xf6,
	0xa0, 0x7f, 0x41, 0xf4, 0xe4, 0xc1, 0x08, 0x0a, 0xde, 0xe2, 0x76, 0x8a, 0x81, 0x9a, 0xc4, 0x76,
	0xb2, 0xfe, 0x33, 0x7f, 0x9f, 0x54, 0xa7, 0x45, 0x57, 0x3d, 0xbe, 0xc7, 0xcb, 0xbc, 0xf7, 0x11,
	0x38, 0x7a, 0x49, 0x1d, 0x39, 0xbb, 0xae, 0xdf, 0x9c, 0x6f, 0xb0, 0x45, 0xdf, 0x60, 0x5f, 0xc7,
	0x3e, 0x50, 0x90, 0xf9, 0x77, 0xcb, 0x46, 0xa7, 0xcf, 0x20, 0xbf, 0x5b, 0x59, 0x7f, 0xe5, 0x3a,
	0x34, 0xf8, 0x9a, 0x70, 0x20, 0x59, 0x42, 0xd6, 0xba, 0x0e, 0xa3, 0xa5, 0xe7, 0x42, 0x28, 0x51,
	0xed, 0x9a, 0x59, 0xeb, 0x47, 0xd8, 0x1b, 0xe3, 0x06, 0x87, 0x18, 0xfc, 0x80, 0xf2, 0x10, 0x96,
	0x21, 0x51, 0x4c, 0xc4, 0x49, 0x56, 0xe3, 0x0d, 0xe7, 0x5b, 0x5c, 0x11, 0x36, 0xc5, 0xb6, 0x12,
	0x55, 0x66, 0x66, 0x3d, 0xbe, 0x49, 0xb1, 0xb1, 0x84, 0xc5, 0x42, 0x89, 0x6a, 0x61, 0x58, 0xe9,
	0x03, 0xd8, 0xbf, 0xc7, 0x7e, 0x70, 0xc1, 0xf3, 0x12, 0x7d, 0x0a, 0xf9, 0xec, 0x70, 0x61, 0x01,
	0x3b, 0xeb, 0x2f, 0x8b, 0x1b, 0x27, 0x79, 0xfe, 0x2e, 0x40, 0x3e, 0x38, 0x7f, 0xc9, 0x74, 0xe3,
	0x4c, 0x8f, 0xbd, 0xbc, 0x81, 0x6c, 0x02, 0x94, 0xaa, 0xde, 0xc0, 0xaf, 0x37, 0xd8, 0xcb, 0xe3,
	0x3f, 0x13, 0x53, 0xbb, 0xde, 0x92, 0xb7, 0x00, 0xd7, 0x48, 0xbc, 0x4a, 0x9e, 0xfc, 0x8a, 0xff,
	0x24, 0x28, 0xd5, 0xff, 0x81, 0xe9, 0xe4, 0xd3, 0xf2, 0xf3, 0x6b, 0x2e, 0x3e, 0x02, 0x00, 0x00,
	0xff, 0xff, 0xa7, 0xd8, 0x93, 0x4b, 0xb7, 0x01, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// WinDefenderScannerClient is the client API for WinDefenderScanner service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type WinDefenderScannerClient interface {
	// Scan a file
	ScanFile(ctx context.Context, in *ScanFileRequest, opts ...grpc.CallOption) (*ScanResponse, error)
	// Get version
	GetVersion(ctx context.Context, in *VersionRequest, opts ...grpc.CallOption) (*VersionResponse, error)
}

type winDefenderScannerClient struct {
	cc *grpc.ClientConn
}

func NewWinDefenderScannerClient(cc *grpc.ClientConn) WinDefenderScannerClient {
	return &winDefenderScannerClient{cc}
}

func (c *winDefenderScannerClient) ScanFile(ctx context.Context, in *ScanFileRequest, opts ...grpc.CallOption) (*ScanResponse, error) {
	out := new(ScanResponse)
	err := c.cc.Invoke(ctx, "/windefender.api.WinDefenderScanner/ScanFile", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *winDefenderScannerClient) GetVersion(ctx context.Context, in *VersionRequest, opts ...grpc.CallOption) (*VersionResponse, error) {
	out := new(VersionResponse)
	err := c.cc.Invoke(ctx, "/windefender.api.WinDefenderScanner/GetVersion", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// WinDefenderScannerServer is the server API for WinDefenderScanner service.
type WinDefenderScannerServer interface {
	// Scan a file
	ScanFile(context.Context, *ScanFileRequest) (*ScanResponse, error)
	// Get version
	GetVersion(context.Context, *VersionRequest) (*VersionResponse, error)
}

// UnimplementedWinDefenderScannerServer can be embedded to have forward compatible implementations.
type UnimplementedWinDefenderScannerServer struct {
}

func (*UnimplementedWinDefenderScannerServer) ScanFile(ctx context.Context, req *ScanFileRequest) (*ScanResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ScanFile not implemented")
}
func (*UnimplementedWinDefenderScannerServer) GetVersion(ctx context.Context, req *VersionRequest) (*VersionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetVersion not implemented")
}

func RegisterWinDefenderScannerServer(s *grpc.Server, srv WinDefenderScannerServer) {
	s.RegisterService(&_WinDefenderScanner_serviceDesc, srv)
}

func _WinDefenderScanner_ScanFile_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ScanFileRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WinDefenderScannerServer).ScanFile(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/windefender.api.WinDefenderScanner/ScanFile",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WinDefenderScannerServer).ScanFile(ctx, req.(*ScanFileRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _WinDefenderScanner_GetVersion_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(VersionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WinDefenderScannerServer).GetVersion(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/windefender.api.WinDefenderScanner/GetVersion",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WinDefenderScannerServer).GetVersion(ctx, req.(*VersionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _WinDefenderScanner_serviceDesc = grpc.ServiceDesc{
	ServiceName: "windefender.api.WinDefenderScanner",
	HandlerType: (*WinDefenderScannerServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ScanFile",
			Handler:    _WinDefenderScanner_ScanFile_Handler,
		},
		{
			MethodName: "GetVersion",
			Handler:    _WinDefenderScanner_GetVersion_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "multiav.windefender.proto",
}
