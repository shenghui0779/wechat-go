package wechat

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSign(t *testing.T) {
	pay := NewPay("10000100", "192006250b4c09247ec02edce69f6a2d")

	params := M{}

	params.Set("appid", "wx2421b1c4370ec43b")
	params.Set("mch_id", pay.MchID())
	params.Set("nonce_str", Nonce(16))
	params.Set("trade_type", "APP")
	params.Set("body", "APP支付测试")
	params.Set("out_trade_no", "1415659990")
	params.Set("total_fee", "1")
	params.Set("fee_type", "CNY")
	params.Set("spbill_create_ip", "14.23.150.211")
	params.Set("notify_url", "http://wxpay.wxutil.com/pub_v2/pay/notify.v2.php")
	params.Set("attach", "支付测试")
	params.Set("sign", pay.Sign(params))

	assert.Nil(t, pay.Verify(params))
}
