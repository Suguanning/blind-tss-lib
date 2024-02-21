// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v4.25.3
// source: protob/ecdsa-blind-signing.proto

package signing

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type SignRound1Message1 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	KrPoint []byte `protobuf:"bytes,1,opt,name=kr_point,json=krPoint,proto3" json:"kr_point,omitempty"`
}

func (x *SignRound1Message1) Reset() {
	*x = SignRound1Message1{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_blind_signing_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound1Message1) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound1Message1) ProtoMessage() {}

func (x *SignRound1Message1) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_blind_signing_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound1Message1.ProtoReflect.Descriptor instead.
func (*SignRound1Message1) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_blind_signing_proto_rawDescGZIP(), []int{0}
}

func (x *SignRound1Message1) GetKrPoint() []byte {
	if x != nil {
		return x.KrPoint
	}
	return nil
}

type SignRound1Message2 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	KrxPoint          []byte `protobuf:"bytes,1,opt,name=krx_point,json=krxPoint,proto3" json:"krx_point,omitempty"`
	PmaskInversePoint []byte `protobuf:"bytes,2,opt,name=pmask_inverse_point,json=pmaskInversePoint,proto3" json:"pmask_inverse_point,omitempty"`
	KPoint            []byte `protobuf:"bytes,3,opt,name=k_point,json=kPoint,proto3" json:"k_point,omitempty"`
	VerifyPoint       []byte `protobuf:"bytes,4,opt,name=verify_point,json=verifyPoint,proto3" json:"verify_point,omitempty"`
}

func (x *SignRound1Message2) Reset() {
	*x = SignRound1Message2{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_blind_signing_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound1Message2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound1Message2) ProtoMessage() {}

func (x *SignRound1Message2) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_blind_signing_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound1Message2.ProtoReflect.Descriptor instead.
func (*SignRound1Message2) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_blind_signing_proto_rawDescGZIP(), []int{1}
}

func (x *SignRound1Message2) GetKrxPoint() []byte {
	if x != nil {
		return x.KrxPoint
	}
	return nil
}

func (x *SignRound1Message2) GetPmaskInversePoint() []byte {
	if x != nil {
		return x.PmaskInversePoint
	}
	return nil
}

func (x *SignRound1Message2) GetKPoint() []byte {
	if x != nil {
		return x.KPoint
	}
	return nil
}

func (x *SignRound1Message2) GetVerifyPoint() []byte {
	if x != nil {
		return x.VerifyPoint
	}
	return nil
}

type SignRound2Message1 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	EncryptMi  []byte `protobuf:"bytes,1,opt,name=encrypt_mi,json=encryptMi,proto3" json:"encrypt_mi,omitempty"`
	EncryptR   []byte `protobuf:"bytes,2,opt,name=encrypt_r,json=encryptR,proto3" json:"encrypt_r,omitempty"`
	EncryptMiA []byte `protobuf:"bytes,3,opt,name=encrypt_mi_a,json=encryptMiA,proto3" json:"encrypt_mi_a,omitempty"`
	EncryptRA  []byte `protobuf:"bytes,4,opt,name=encrypt_r_a,json=encryptRA,proto3" json:"encrypt_r_a,omitempty"`
	Index      []byte `protobuf:"bytes,5,opt,name=index,proto3" json:"index,omitempty"`
}

func (x *SignRound2Message1) Reset() {
	*x = SignRound2Message1{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_blind_signing_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound2Message1) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound2Message1) ProtoMessage() {}

func (x *SignRound2Message1) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_blind_signing_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound2Message1.ProtoReflect.Descriptor instead.
func (*SignRound2Message1) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_blind_signing_proto_rawDescGZIP(), []int{2}
}

func (x *SignRound2Message1) GetEncryptMi() []byte {
	if x != nil {
		return x.EncryptMi
	}
	return nil
}

func (x *SignRound2Message1) GetEncryptR() []byte {
	if x != nil {
		return x.EncryptR
	}
	return nil
}

func (x *SignRound2Message1) GetEncryptMiA() []byte {
	if x != nil {
		return x.EncryptMiA
	}
	return nil
}

func (x *SignRound2Message1) GetEncryptRA() []byte {
	if x != nil {
		return x.EncryptRA
	}
	return nil
}

func (x *SignRound2Message1) GetIndex() []byte {
	if x != nil {
		return x.Index
	}
	return nil
}

type SignRound2Message2 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	EncryptS  []byte `protobuf:"bytes,1,opt,name=encrypt_s,json=encryptS,proto3" json:"encrypt_s,omitempty"`
	EncryptSA []byte `protobuf:"bytes,2,opt,name=encrypt_s_a,json=encryptSA,proto3" json:"encrypt_s_a,omitempty"`
	SharePont []byte `protobuf:"bytes,3,opt,name=share_pont,json=sharePont,proto3" json:"share_pont,omitempty"`
}

func (x *SignRound2Message2) Reset() {
	*x = SignRound2Message2{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_blind_signing_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound2Message2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound2Message2) ProtoMessage() {}

func (x *SignRound2Message2) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_blind_signing_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound2Message2.ProtoReflect.Descriptor instead.
func (*SignRound2Message2) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_blind_signing_proto_rawDescGZIP(), []int{3}
}

func (x *SignRound2Message2) GetEncryptS() []byte {
	if x != nil {
		return x.EncryptS
	}
	return nil
}

func (x *SignRound2Message2) GetEncryptSA() []byte {
	if x != nil {
		return x.EncryptSA
	}
	return nil
}

func (x *SignRound2Message2) GetSharePont() []byte {
	if x != nil {
		return x.SharePont
	}
	return nil
}

var File_protob_ecdsa_blind_signing_proto protoreflect.FileDescriptor

var file_protob_ecdsa_blind_signing_proto_rawDesc = []byte{
	0x0a, 0x20, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x2f, 0x65, 0x63, 0x64, 0x73, 0x61, 0x2d, 0x62,
	0x6c, 0x69, 0x6e, 0x64, 0x2d, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x12, 0x1c, 0x62, 0x69, 0x6e, 0x61, 0x6e, 0x63, 0x65, 0x2e, 0x74, 0x73, 0x73, 0x6c,
	0x69, 0x62, 0x2e, 0x65, 0x63, 0x64, 0x73, 0x61, 0x2e, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67,
	0x22, 0x2f, 0x0a, 0x12, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x31, 0x4d, 0x65,
	0x73, 0x73, 0x61, 0x67, 0x65, 0x31, 0x12, 0x19, 0x0a, 0x08, 0x6b, 0x72, 0x5f, 0x70, 0x6f, 0x69,
	0x6e, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x6b, 0x72, 0x50, 0x6f, 0x69, 0x6e,
	0x74, 0x22, 0x9d, 0x01, 0x0a, 0x12, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x31,
	0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x32, 0x12, 0x1b, 0x0a, 0x09, 0x6b, 0x72, 0x78, 0x5f,
	0x70, 0x6f, 0x69, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x08, 0x6b, 0x72, 0x78,
	0x50, 0x6f, 0x69, 0x6e, 0x74, 0x12, 0x2e, 0x0a, 0x13, 0x70, 0x6d, 0x61, 0x73, 0x6b, 0x5f, 0x69,
	0x6e, 0x76, 0x65, 0x72, 0x73, 0x65, 0x5f, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x11, 0x70, 0x6d, 0x61, 0x73, 0x6b, 0x49, 0x6e, 0x76, 0x65, 0x72, 0x73, 0x65,
	0x50, 0x6f, 0x69, 0x6e, 0x74, 0x12, 0x17, 0x0a, 0x07, 0x6b, 0x5f, 0x70, 0x6f, 0x69, 0x6e, 0x74,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x6b, 0x50, 0x6f, 0x69, 0x6e, 0x74, 0x12, 0x21,
	0x0a, 0x0c, 0x76, 0x65, 0x72, 0x69, 0x66, 0x79, 0x5f, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x76, 0x65, 0x72, 0x69, 0x66, 0x79, 0x50, 0x6f, 0x69, 0x6e,
	0x74, 0x22, 0xa8, 0x01, 0x0a, 0x12, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x32,
	0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x31, 0x12, 0x1d, 0x0a, 0x0a, 0x65, 0x6e, 0x63, 0x72,
	0x79, 0x70, 0x74, 0x5f, 0x6d, 0x69, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x65, 0x6e,
	0x63, 0x72, 0x79, 0x70, 0x74, 0x4d, 0x69, 0x12, 0x1b, 0x0a, 0x09, 0x65, 0x6e, 0x63, 0x72, 0x79,
	0x70, 0x74, 0x5f, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x08, 0x65, 0x6e, 0x63, 0x72,
	0x79, 0x70, 0x74, 0x52, 0x12, 0x20, 0x0a, 0x0c, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x5f,
	0x6d, 0x69, 0x5f, 0x61, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0a, 0x65, 0x6e, 0x63, 0x72,
	0x79, 0x70, 0x74, 0x4d, 0x69, 0x41, 0x12, 0x1e, 0x0a, 0x0b, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70,
	0x74, 0x5f, 0x72, 0x5f, 0x61, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x65, 0x6e, 0x63,
	0x72, 0x79, 0x70, 0x74, 0x52, 0x41, 0x12, 0x14, 0x0a, 0x05, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x18,
	0x05, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x22, 0x70, 0x0a, 0x12,
	0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x32, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67,
	0x65, 0x32, 0x12, 0x1b, 0x0a, 0x09, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x5f, 0x73, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x08, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x53, 0x12,
	0x1e, 0x0a, 0x0b, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x5f, 0x73, 0x5f, 0x61, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x53, 0x41, 0x12,
	0x1d, 0x0a, 0x0a, 0x73, 0x68, 0x61, 0x72, 0x65, 0x5f, 0x70, 0x6f, 0x6e, 0x74, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x68, 0x61, 0x72, 0x65, 0x50, 0x6f, 0x6e, 0x74, 0x42, 0x15,
	0x5a, 0x13, 0x65, 0x63, 0x64, 0x73, 0x61, 0x2d, 0x62, 0x6c, 0x69, 0x6e, 0x64, 0x2f, 0x73, 0x69,
	0x67, 0x6e, 0x69, 0x6e, 0x67, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_protob_ecdsa_blind_signing_proto_rawDescOnce sync.Once
	file_protob_ecdsa_blind_signing_proto_rawDescData = file_protob_ecdsa_blind_signing_proto_rawDesc
)

func file_protob_ecdsa_blind_signing_proto_rawDescGZIP() []byte {
	file_protob_ecdsa_blind_signing_proto_rawDescOnce.Do(func() {
		file_protob_ecdsa_blind_signing_proto_rawDescData = protoimpl.X.CompressGZIP(file_protob_ecdsa_blind_signing_proto_rawDescData)
	})
	return file_protob_ecdsa_blind_signing_proto_rawDescData
}

var file_protob_ecdsa_blind_signing_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_protob_ecdsa_blind_signing_proto_goTypes = []interface{}{
	(*SignRound1Message1)(nil), // 0: binance.tsslib.ecdsa.signing.SignRound1Message1
	(*SignRound1Message2)(nil), // 1: binance.tsslib.ecdsa.signing.SignRound1Message2
	(*SignRound2Message1)(nil), // 2: binance.tsslib.ecdsa.signing.SignRound2Message1
	(*SignRound2Message2)(nil), // 3: binance.tsslib.ecdsa.signing.SignRound2Message2
}
var file_protob_ecdsa_blind_signing_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_protob_ecdsa_blind_signing_proto_init() }
func file_protob_ecdsa_blind_signing_proto_init() {
	if File_protob_ecdsa_blind_signing_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_protob_ecdsa_blind_signing_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound1Message1); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protob_ecdsa_blind_signing_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound1Message2); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protob_ecdsa_blind_signing_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound2Message1); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protob_ecdsa_blind_signing_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound2Message2); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_protob_ecdsa_blind_signing_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_protob_ecdsa_blind_signing_proto_goTypes,
		DependencyIndexes: file_protob_ecdsa_blind_signing_proto_depIdxs,
		MessageInfos:      file_protob_ecdsa_blind_signing_proto_msgTypes,
	}.Build()
	File_protob_ecdsa_blind_signing_proto = out.File
	file_protob_ecdsa_blind_signing_proto_rawDesc = nil
	file_protob_ecdsa_blind_signing_proto_goTypes = nil
	file_protob_ecdsa_blind_signing_proto_depIdxs = nil
}
