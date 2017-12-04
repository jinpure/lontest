package lontest

import (
	"encoding/binary"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	LayerTypeTimestamp = gopacket.RegisterLayerType(124, gopacket.LayerTypeMetadata{Name: "Timestamp", Decoder: gopacket.DecodeFunc(decodeTimestamp)})
)

type TimestampLayer struct {
	layers.BaseLayer
	Timestamp int64
}

//implement CanDecode method DecodingLayer of interface
func (this *TimestampLayer) CanDecode() gopacket.LayerClass {
	return LayerTypeTimestamp
}

//implement NextLayerType method DecodingLayer of interface
func (this *TimestampLayer) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

//implement LayerType method of Layer interface
func (this *TimestampLayer) LayerType() gopacket.LayerType {
	return LayerTypeTimestamp
}

//implement Payload method of ApplicationLayer interface
func (this *TimestampLayer) Payload() []byte {
	return nil
}
func decodeTimestamp(data []byte, builder gopacket.PacketBuilder) error {
	ts := &TimestampLayer{}
	builder.AddLayer(ts)
	builder.SetApplicationLayer(ts)
	log.Println("data", data)
	err := ts.DecodeFromBytes(data, builder)
	if err != nil {
		return err
	}

	return nil
}

//implement DecodeFromBytes method DecodingLayer of interface
func (this *TimestampLayer) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	log.Println("data", data)
	this.BaseLayer = layers.BaseLayer{Contents: data[:8]}
	this.Timestamp = int64(binary.BigEndian.Uint64(data[:8]))
	return nil
}
