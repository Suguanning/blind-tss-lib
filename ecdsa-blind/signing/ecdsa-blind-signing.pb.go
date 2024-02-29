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

	BigKrX []byte `protobuf:"bytes,1,opt,name=BigKr_x,json=BigKrX,proto3" json:"BigKr_x,omitempty"`
	BigKrY []byte `protobuf:"bytes,2,opt,name=BigKr_y,json=BigKrY,proto3" json:"BigKr_y,omitempty"`
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

func (x *SignRound1Message1) GetBigKrX() []byte {
	if x != nil {
		return x.BigKrX
	}
	return nil
}

func (x *SignRound1Message1) GetBigKrY() []byte {
	if x != nil {
		return x.BigKrY
	}
	return nil
}

type SignRound1Message2 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BigKrxX []byte `protobuf:"bytes,1,opt,name=BigKrx_x,json=BigKrxX,proto3" json:"BigKrx_x,omitempty"`
	BigKrxY []byte `protobuf:"bytes,2,opt,name=BigKrx_y,json=BigKrxY,proto3" json:"BigKrx_y,omitempty"`
	BigPi_X []byte `protobuf:"bytes,3,opt,name=BigPi__x,json=BigPiX,proto3" json:"BigPi__x,omitempty"`
	BigPi_Y []byte `protobuf:"bytes,4,opt,name=BigPi__y,json=BigPiY,proto3" json:"BigPi__y,omitempty"`
	BigKiX  []byte `protobuf:"bytes,5,opt,name=BigKi_x,json=BigKiX,proto3" json:"BigKi_x,omitempty"`
	BigKiY  []byte `protobuf:"bytes,6,opt,name=BigKi_y,json=BigKiY,proto3" json:"BigKi_y,omitempty"`
	BigViX  []byte `protobuf:"bytes,7,opt,name=BigVi_x,json=BigViX,proto3" json:"BigVi_x,omitempty"`
	BigViY  []byte `protobuf:"bytes,8,opt,name=BigVi_y,json=BigViY,proto3" json:"BigVi_y,omitempty"`
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

func (x *SignRound1Message2) GetBigKrxX() []byte {
	if x != nil {
		return x.BigKrxX
	}
	return nil
}

func (x *SignRound1Message2) GetBigKrxY() []byte {
	if x != nil {
		return x.BigKrxY
	}
	return nil
}

func (x *SignRound1Message2) GetBigPi_X() []byte {
	if x != nil {
		return x.BigPi_X
	}
	return nil
}

func (x *SignRound1Message2) GetBigPi_Y() []byte {
	if x != nil {
		return x.BigPi_Y
	}
	return nil
}

func (x *SignRound1Message2) GetBigKiX() []byte {
	if x != nil {
		return x.BigKiX
	}
	return nil
}

func (x *SignRound1Message2) GetBigKiY() []byte {
	if x != nil {
		return x.BigKiY
	}
	return nil
}

func (x *SignRound1Message2) GetBigViX() []byte {
	if x != nil {
		return x.BigViX
	}
	return nil
}

func (x *SignRound1Message2) GetBigViY() []byte {
	if x != nil {
		return x.BigViY
	}
	return nil
}

type SignRound2Message1 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Cmi   []byte `protobuf:"bytes,1,opt,name=Cmi,proto3" json:"Cmi,omitempty"`
	Cr    []byte `protobuf:"bytes,2,opt,name=Cr,proto3" json:"Cr,omitempty"`
	CmiA  []byte `protobuf:"bytes,3,opt,name=Cmi_a,json=CmiA,proto3" json:"Cmi_a,omitempty"`
	CrA   []byte `protobuf:"bytes,4,opt,name=Cr_a,json=CrA,proto3" json:"Cr_a,omitempty"`
	N     []byte `protobuf:"bytes,5,opt,name=N,proto3" json:"N,omitempty"`
	Index []byte `protobuf:"bytes,6,opt,name=index,proto3" json:"index,omitempty"`
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

func (x *SignRound2Message1) GetCmi() []byte {
	if x != nil {
		return x.Cmi
	}
	return nil
}

func (x *SignRound2Message1) GetCr() []byte {
	if x != nil {
		return x.Cr
	}
	return nil
}

func (x *SignRound2Message1) GetCmiA() []byte {
	if x != nil {
		return x.CmiA
	}
	return nil
}

func (x *SignRound2Message1) GetCrA() []byte {
	if x != nil {
		return x.CrA
	}
	return nil
}

func (x *SignRound2Message1) GetN() []byte {
	if x != nil {
		return x.N
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

	Ci     []byte `protobuf:"bytes,1,opt,name=Ci,proto3" json:"Ci,omitempty"`
	CiA    []byte `protobuf:"bytes,2,opt,name=Ci_a,json=CiA,proto3" json:"Ci_a,omitempty"`
	BigXiX []byte `protobuf:"bytes,3,opt,name=bigXi_x,json=bigXiX,proto3" json:"bigXi_x,omitempty"`
	BigXiY []byte `protobuf:"bytes,4,opt,name=bigXi_y,json=bigXiY,proto3" json:"bigXi_y,omitempty"`
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

func (x *SignRound2Message2) GetCi() []byte {
	if x != nil {
		return x.Ci
	}
	return nil
}

func (x *SignRound2Message2) GetCiA() []byte {
	if x != nil {
		return x.CiA
	}
	return nil
}

func (x *SignRound2Message2) GetBigXiX() []byte {
	if x != nil {
		return x.BigXiX
	}
	return nil
}

func (x *SignRound2Message2) GetBigXiY() []byte {
	if x != nil {
		return x.BigXiY
	}
	return nil
}

type SignRound3Message1 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Ci  []byte `protobuf:"bytes,1,opt,name=Ci,proto3" json:"Ci,omitempty"`
	CiA []byte `protobuf:"bytes,2,opt,name=Ci_a,json=CiA,proto3" json:"Ci_a,omitempty"`
	N   []byte `protobuf:"bytes,3,opt,name=N,proto3" json:"N,omitempty"`
}

func (x *SignRound3Message1) Reset() {
	*x = SignRound3Message1{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_blind_signing_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound3Message1) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound3Message1) ProtoMessage() {}

func (x *SignRound3Message1) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_blind_signing_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound3Message1.ProtoReflect.Descriptor instead.
func (*SignRound3Message1) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_blind_signing_proto_rawDescGZIP(), []int{4}
}

func (x *SignRound3Message1) GetCi() []byte {
	if x != nil {
		return x.Ci
	}
	return nil
}

func (x *SignRound3Message1) GetCiA() []byte {
	if x != nil {
		return x.CiA
	}
	return nil
}

func (x *SignRound3Message1) GetN() []byte {
	if x != nil {
		return x.N
	}
	return nil
}

type SignRound3Message2 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Ci  []byte `protobuf:"bytes,1,opt,name=Ci,proto3" json:"Ci,omitempty"`
	CiA []byte `protobuf:"bytes,2,opt,name=Ci_a,json=CiA,proto3" json:"Ci_a,omitempty"`
}

func (x *SignRound3Message2) Reset() {
	*x = SignRound3Message2{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_blind_signing_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound3Message2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound3Message2) ProtoMessage() {}

func (x *SignRound3Message2) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_blind_signing_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound3Message2.ProtoReflect.Descriptor instead.
func (*SignRound3Message2) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_blind_signing_proto_rawDescGZIP(), []int{5}
}

func (x *SignRound3Message2) GetCi() []byte {
	if x != nil {
		return x.Ci
	}
	return nil
}

func (x *SignRound3Message2) GetCiA() []byte {
	if x != nil {
		return x.CiA
	}
	return nil
}

var File_protob_ecdsa_blind_signing_proto protoreflect.FileDescriptor

var file_protob_ecdsa_blind_signing_proto_rawDesc = []byte{
	0x0a, 0x20, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x2f, 0x65, 0x63, 0x64, 0x73, 0x61, 0x2d, 0x62,
	0x6c, 0x69, 0x6e, 0x64, 0x2d, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x12, 0x1c, 0x62, 0x69, 0x6e, 0x61, 0x6e, 0x63, 0x65, 0x2e, 0x74, 0x73, 0x73, 0x6c,
	0x69, 0x62, 0x2e, 0x65, 0x63, 0x64, 0x73, 0x61, 0x2e, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67,
	0x22, 0x46, 0x0a, 0x12, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x31, 0x4d, 0x65,
	0x73, 0x73, 0x61, 0x67, 0x65, 0x31, 0x12, 0x17, 0x0a, 0x07, 0x42, 0x69, 0x67, 0x4b, 0x72, 0x5f,
	0x78, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x42, 0x69, 0x67, 0x4b, 0x72, 0x58, 0x12,
	0x17, 0x0a, 0x07, 0x42, 0x69, 0x67, 0x4b, 0x72, 0x5f, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x06, 0x42, 0x69, 0x67, 0x4b, 0x72, 0x59, 0x22, 0xe2, 0x01, 0x0a, 0x12, 0x53, 0x69, 0x67,
	0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x31, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x32, 0x12,
	0x19, 0x0a, 0x08, 0x42, 0x69, 0x67, 0x4b, 0x72, 0x78, 0x5f, 0x78, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x07, 0x42, 0x69, 0x67, 0x4b, 0x72, 0x78, 0x58, 0x12, 0x19, 0x0a, 0x08, 0x42, 0x69,
	0x67, 0x4b, 0x72, 0x78, 0x5f, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x42, 0x69,
	0x67, 0x4b, 0x72, 0x78, 0x59, 0x12, 0x18, 0x0a, 0x08, 0x42, 0x69, 0x67, 0x50, 0x69, 0x5f, 0x5f,
	0x78, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x42, 0x69, 0x67, 0x50, 0x69, 0x58, 0x12,
	0x18, 0x0a, 0x08, 0x42, 0x69, 0x67, 0x50, 0x69, 0x5f, 0x5f, 0x79, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x06, 0x42, 0x69, 0x67, 0x50, 0x69, 0x59, 0x12, 0x17, 0x0a, 0x07, 0x42, 0x69, 0x67,
	0x4b, 0x69, 0x5f, 0x78, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x42, 0x69, 0x67, 0x4b,
	0x69, 0x58, 0x12, 0x17, 0x0a, 0x07, 0x42, 0x69, 0x67, 0x4b, 0x69, 0x5f, 0x79, 0x18, 0x06, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x06, 0x42, 0x69, 0x67, 0x4b, 0x69, 0x59, 0x12, 0x17, 0x0a, 0x07, 0x42,
	0x69, 0x67, 0x56, 0x69, 0x5f, 0x78, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x42, 0x69,
	0x67, 0x56, 0x69, 0x58, 0x12, 0x17, 0x0a, 0x07, 0x42, 0x69, 0x67, 0x56, 0x69, 0x5f, 0x79, 0x18,
	0x08, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x42, 0x69, 0x67, 0x56, 0x69, 0x59, 0x22, 0x82, 0x01,
	0x0a, 0x12, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x32, 0x4d, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x31, 0x12, 0x10, 0x0a, 0x03, 0x43, 0x6d, 0x69, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x03, 0x43, 0x6d, 0x69, 0x12, 0x0e, 0x0a, 0x02, 0x43, 0x72, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x02, 0x43, 0x72, 0x12, 0x13, 0x0a, 0x05, 0x43, 0x6d, 0x69, 0x5f, 0x61, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x43, 0x6d, 0x69, 0x41, 0x12, 0x11, 0x0a, 0x04, 0x43,
	0x72, 0x5f, 0x61, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03, 0x43, 0x72, 0x41, 0x12, 0x0c,
	0x0a, 0x01, 0x4e, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x4e, 0x12, 0x14, 0x0a, 0x05,
	0x69, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x69, 0x6e, 0x64,
	0x65, 0x78, 0x22, 0x69, 0x0a, 0x12, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x32,
	0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x32, 0x12, 0x0e, 0x0a, 0x02, 0x43, 0x69, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x43, 0x69, 0x12, 0x11, 0x0a, 0x04, 0x43, 0x69, 0x5f, 0x61,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03, 0x43, 0x69, 0x41, 0x12, 0x17, 0x0a, 0x07, 0x62,
	0x69, 0x67, 0x58, 0x69, 0x5f, 0x78, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x62, 0x69,
	0x67, 0x58, 0x69, 0x58, 0x12, 0x17, 0x0a, 0x07, 0x62, 0x69, 0x67, 0x58, 0x69, 0x5f, 0x79, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x62, 0x69, 0x67, 0x58, 0x69, 0x59, 0x22, 0x45, 0x0a,
	0x12, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x33, 0x4d, 0x65, 0x73, 0x73, 0x61,
	0x67, 0x65, 0x31, 0x12, 0x0e, 0x0a, 0x02, 0x43, 0x69, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x02, 0x43, 0x69, 0x12, 0x11, 0x0a, 0x04, 0x43, 0x69, 0x5f, 0x61, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x03, 0x43, 0x69, 0x41, 0x12, 0x0c, 0x0a, 0x01, 0x4e, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x01, 0x4e, 0x22, 0x37, 0x0a, 0x12, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e,
	0x64, 0x33, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x32, 0x12, 0x0e, 0x0a, 0x02, 0x43, 0x69,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x43, 0x69, 0x12, 0x11, 0x0a, 0x04, 0x43, 0x69,
	0x5f, 0x61, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03, 0x43, 0x69, 0x41, 0x42, 0x15, 0x5a,
	0x13, 0x65, 0x63, 0x64, 0x73, 0x61, 0x2d, 0x62, 0x6c, 0x69, 0x6e, 0x64, 0x2f, 0x73, 0x69, 0x67,
	0x6e, 0x69, 0x6e, 0x67, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
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

var file_protob_ecdsa_blind_signing_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_protob_ecdsa_blind_signing_proto_goTypes = []interface{}{
	(*SignRound1Message1)(nil), // 0: binance.tsslib.ecdsa.signing.SignRound1Message1
	(*SignRound1Message2)(nil), // 1: binance.tsslib.ecdsa.signing.SignRound1Message2
	(*SignRound2Message1)(nil), // 2: binance.tsslib.ecdsa.signing.SignRound2Message1
	(*SignRound2Message2)(nil), // 3: binance.tsslib.ecdsa.signing.SignRound2Message2
	(*SignRound3Message1)(nil), // 4: binance.tsslib.ecdsa.signing.SignRound3Message1
	(*SignRound3Message2)(nil), // 5: binance.tsslib.ecdsa.signing.SignRound3Message2
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
		file_protob_ecdsa_blind_signing_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound3Message1); i {
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
		file_protob_ecdsa_blind_signing_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound3Message2); i {
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
			NumMessages:   6,
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
