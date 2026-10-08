package identityv1

import "context"

type fakeAccounts struct{}

func (fakeAccounts) RequestVerification(context.Context, string) error   { return nil }
func (fakeAccounts) RequestPasswordReset(context.Context, string) error  { return nil }
func (fakeAccounts) VerifyEmail(context.Context, string) error           { return nil }
func (fakeAccounts) ResetPassword(context.Context, string, string) error { return nil }
