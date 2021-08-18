package yespower

import "testing"

func TestGood(t *testing.T) {

	examples := []struct {
		N, r            int
		persToken, want string
	}{
		{N: 2048, r: 8, persToken: "", want: "69e0e895b3df7aeeb837d71fe199e9d34f7ec46ecbca7a2c4308e51857ae9b46"},
		{N: 4096, r: 16, persToken: "", want: "33fb8f063824a4a020f63dca535f5ca66ab5576468c75d1ccaac7542f76495ac"},
		{N: 4096, r: 32, persToken: "", want: "771aeefda8fe79a0825bc7f2aee162ab5578574639ffc6ca3723cc18e5e3e285"},
		{N: 2048, r: 32, persToken: "", want: "d5efb813cd263e9b34540130233cbbc6a921fbff3431e5ec1a1abde2aea6ff4d"},
		{N: 1024, r: 32, persToken: "", want: "501b792db42e388f6e7d453c95d03a12a36016a5154a688390ddc609a40c6799"},
		{N: 1024, r: 32, persToken: "personality test", want: "1f0269acf565c49adc0ef9b8f26ab3808cdc38394a254fddeedcc3aacff6ad9d"},
	}

	for _, tt := range examples {
		got := Yespower(tt.N, tt.r, tt.persToken)
		if got != tt.want {
			t.Errorf("got %s want %s", got, tt.want)
		}
	}
}

// func TestBad(t *testing.T) {
//
// 	examples := []struct {
// 		N, r            int
// 		persToken, want string
// 	}{
// 		{N: 2048, r: 8, persToken: "", want: "69e0e895b3df7aeeb837d71fe199e9d34f7ec46ecbca7a2c4308e51857ae9b46"},
// 		{N: 4096, r: 16, persToken: "", want: "33fb8f063824a4a020f63dca535f5ca66ab5576468c75d1ccaac7542f76495ac"},
// 		{N: 4096, r: 32, persToken: "", want: "771aeefda8fe79a0825bc7f2aee162ab5578574639ffc6ca3723cc18e5e3e285"},
// 		{N: 2048, r: 32, persToken: "", want: "d5efb813cd263e9b34540130233cbbc6a921fbff3431e5ec1a1abde2aea6ff4d"},
// 		{N: 1024, r: 32, persToken: "", want: "501b792db42e388f6e7d453c95d03a12a36016a5154a688390ddc609a40c6799"},
// 		{N: 1024, r: 32, persToken: "personality test", want: "1f0269acf565c49adc0ef9b8f26ab3808cdc38394a254fddeedcc3aacff6ad9d"},
// 	}
//
// 	for _, tt := range examples {
// 		got := Yespower(tt.N, tt.r, tt.persToken)
// 		if got != tt.want {
// 			t.Errorf("got %s want %s", got, tt.want)
// 		}
// 	}
// }
