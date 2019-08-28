package logformat

import (
	"bytes"
	"github.com/sirupsen/logrus"
	capnp "zombiezen.com/go/capnproto2"
)

type CapnpRequestLogFormatter struct{}

func (f *CapnpRequestLogFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		return []byte{}, err
	}
	requestLog, err := NewRootRequestLog(seg)
	if err != nil {
		return []byte{}, err
	}
	requestLog.SetTimestamp(uint64(entry.Time.Unix()))
	if err = requestLog.SetUuid(entry.Data["domain_uuid"].(string)); err != nil {
		return []byte{}, err
	}
	if err = requestLog.SetRecord(entry.Data["record"].(string)); err != nil {
		return []byte{}, err
	}
	if err = requestLog.SetType(entry.Data["type"].(string)); err != nil {
		return []byte{}, err
	}
	requestLog.SetResponsecode(uint16(entry.Data["response_code"].(int)))
	requestLog.SetProcesstime(uint16(entry.Data["process_time"].(int64)))
	if err = requestLog.SetCache(entry.Data["cache"].(string)); err != nil {
		return []byte{}, err
	}

	clientSubnet, ok := entry.Data["client_subnet"]
	if ok {
		if err = requestLog.SetIp(clientSubnet.(string)); err != nil {
			return []byte{}, err
		}
	}
	sourceCountry, ok := entry.Data["source_country"]
	if ok {
		if err = requestLog.SetCountry(sourceCountry.(string)); err != nil {
			return []byte{}, err
		}
	}
	sourceAsn, ok := entry.Data["source_asn"]
	if ok {
		requestLog.SetAsn(uint32(sourceAsn.(uint)))
	}
	b := &bytes.Buffer{}
	err = capnp.NewEncoder(b).Encode(msg)
	if err != nil {
		return []byte{}, err
	}

	return b.Bytes(), err
}
