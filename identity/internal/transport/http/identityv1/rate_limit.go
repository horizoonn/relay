package identityv1

import (
	"errors"
	"net/http"
	"net/netip"

	identityapi "github.com/horizoonn/relay/shared/pkg/openapi/identity/v1"
)

func clientIP(r *http.Request, trusted []netip.Prefix) (string, error) {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return "", errors.New("invalid peer address")
	}
	address := peer.Addr().Unmap()
	for _, prefix := range trusted {
		if !prefix.Contains(address) {
			continue
		}
		values := r.Header.Values("X-Forwarded-For")
		if len(values) != 1 {
			return "", errors.New("trusted proxy must provide one client address")
		}
		address, err = netip.ParseAddr(values[0])
		if err != nil || address.Zone() != "" {
			return "", errors.New("invalid forwarded client address")
		}
		address = address.Unmap()
		break
	}

	if address.Is6() {
		return netip.PrefixFrom(address, 64).Masked().String(), nil
	}
	return address.String(), nil
}

func (h *Handler) limitRequests(next http.Handler, trusted []netip.Prefix) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scope := policyFor(r).scope
		if scope == "" {
			next.ServeHTTP(w, r)
			return
		}
		ip, err := clientIP(r, trusted)
		if err != nil {
			h.writeProblem(
				w,
				problemFor(
					r.Context(),
					http.StatusBadRequest,
					identityapi.ProblemCodeINVALIDREQUEST,
					"Invalid request",
					"Invalid client address",
				),
			)
			return
		}
		if err := h.limiter.Allow(r.Context(), scope, ip); err != nil {
			h.writeProblem(w, h.NewError(r.Context(), err))
			return
		}
		next.ServeHTTP(w, r)
	})
}
