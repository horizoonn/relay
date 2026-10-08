package password

import "testing"

func BenchmarkVerify(b *testing.B) {
	const value = "benchmark-password-with-enough-length"
	hash, err := Hash(value)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if matched, verifyErr := Verify(value, hash); verifyErr != nil || !matched {
			b.Fatal("password verification failed", verifyErr)
		}
	}
}
