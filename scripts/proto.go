package main

import (
	"fmt"
	"io"
	"net"
	"strings"
)

func pbReadVarint(data []byte, pos int) (uint64, int, error) {
	var result uint64
	shift := 0
	for pos < len(data) {
		b := data[pos]
		pos++
		result |= uint64(b&0x7F) << shift
		if b < 0x80 {
			return result, pos, nil
		}
		shift += 7
	}
	return 0, pos, io.ErrUnexpectedEOF
}

func pbIterFields(data []byte, fn func(fieldNum, wireType int, raw []byte, varint uint64)) {
	pos := 0
	for pos < len(data) {
		tag, p, err := pbReadVarint(data, pos)
		if err != nil {
			return
		}
		pos = p
		fieldNum := int(tag >> 3)
		wireType := int(tag & 7)
		switch wireType {
		case 0:
			v, p2, err := pbReadVarint(data, pos)
			if err != nil {
				return
			}
			pos = p2
			fn(fieldNum, wireType, nil, v)
		case 2:
			length, p2, err := pbReadVarint(data, pos)
			if err != nil {
				return
			}
			end := p2 + int(length)
			if end > len(data) {
				return
			}
			fn(fieldNum, wireType, data[p2:end], 0)
			pos = end
		default:
			return
		}
	}
}

func parseGeoSiteDat(data []byte, out tagSet) {
	pbIterFields(data, func(fn, wt int, raw []byte, _ uint64) {
		if fn != 1 || wt != 2 {
			return
		}
		var code string
		pbIterFields(raw, func(sfn, swt int, sb []byte, _ uint64) {
			if sfn == 1 && swt == 2 {
				code = strings.ToLower(string(sb))
			}
		})
		if code == "" || isCNTag(code) {
			return
		}
		code = normalizeTag(code)
		if isExcludedTag(code) {
			return
		}
		pbIterFields(raw, func(sfn, swt int, sb []byte, _ uint64) {
			if sfn != 2 || swt != 2 {
				return
			}
			var domType uint64 = 2
			var domValue string
			pbIterFields(sb, func(dfn, _ int, db []byte, dv uint64) {
				if dfn == 1 {
					domType = dv
				} else if dfn == 2 {
					domValue = string(db)
				}
			})
			if domValue == "" {
				return
			}
			switch domType {
			case 2, 3:
				if strings.Contains(domValue, ".") && !cnDomainRE.MatchString(domValue) {
					out.add(code, domValue)
				}
			case 1:
				if d := extractDomainFromRegex(domValue); d != "" && !cnDomainRE.MatchString(d) {
					out.add(code, d)
				}
			}
		})
	})
}

func parseGeoIPDat(data []byte, out tagSet) {
	pbIterFields(data, func(fn, wt int, raw []byte, _ uint64) {
		if fn != 1 || wt != 2 {
			return
		}
		var code string
		pbIterFields(raw, func(sfn, swt int, sb []byte, _ uint64) {
			if sfn == 1 && swt == 2 {
				code = strings.ToLower(string(sb))
			}
		})
		if code == "" || isCNTag(code) {
			return
		}
		code = normalizeTag(code)
		if isExcludedTag(code) {
			return
		}
		pbIterFields(raw, func(sfn, swt int, sb []byte, _ uint64) {
			if sfn != 2 || swt != 2 {
				return
			}
			var ipBytes []byte
			var prefix uint64
			pbIterFields(sb, func(dfn, dwt int, db []byte, dv uint64) {
				if dfn == 1 && dwt == 2 {
					ipBytes = db
				} else if dfn == 2 {
					prefix = dv
				}
			})
			if len(ipBytes) == 4 {
				out.add(code, fmt.Sprintf("%s/%d", net.IP(ipBytes).String(), prefix))
			} else if len(ipBytes) == 16 {
				out.add(code, fmt.Sprintf("%s/%d", net.IP(ipBytes).String(), prefix))
			}
		})
	})
}
