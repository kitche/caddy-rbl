package rbl

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(RBL{})
	httpcaddyfile.RegisterHandlerDirective("rbl", parseCaddyfile)
}

// RBL implements an HTTP handler that checks client IPs against RBL lists
type RBL struct {
	// Lists contains the RBL servers to query (e.g., "zen.spamhaus.org")
	Lists []string `json:"lists,omitempty"`
	
	// BlockMessage is the message returned when an IP is blocked
	BlockMessage string `json:"block_message,omitempty"`
	
	// StatusCode is the HTTP status code to return when blocking
	StatusCode int `json:"status_code,omitempty"`
	
	// LogAllChecks determines whether to log all RBL checks or only blocks
	LogAllChecks bool `json:"log_all_checks,omitempty"`
	
	// Logger instance
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information
func (RBL) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.rbl",
		New: func() caddy.Module { return new(RBL) },
	}
}

// Provision sets up the RBL module
func (r *RBL) Provision(ctx caddy.Context) error {
	if len(r.Lists) == 0 {
		return fmt.Errorf("at least one RBL list must be specified")
	}
	
	if r.BlockMessage == "" {
		r.BlockMessage = "Access denied: IP address is listed in RBL"
	}
	
	if r.StatusCode == 0 {
		r.StatusCode = http.StatusForbidden
	}
	
	// Set up logger
	r.logger = ctx.Logger(r)
	
	return nil
}

// Validate ensures the module configuration is valid
func (r *RBL) Validate() error {
	if r.StatusCode < 100 || r.StatusCode > 599 {
		return fmt.Errorf("invalid status code: %d", r.StatusCode)
	}
	return nil
}

// ServeHTTP implements the caddyhttp.MiddlewareHandler interface
func (r RBL) ServeHTTP(w http.ResponseWriter, req *http.Request, next caddyhttp.Handler) error {
	clientIP := getClientIP(req)
	
	if clientIP == "" {
		r.logger.Warn("unable to determine client IP",
			zap.String("remote_addr", req.RemoteAddr),
		)
		return next.ServeHTTP(w, req)
	}
	
	// Check if IP is listed in any RBL
	listed, rblServer := r.checkRBL(clientIP)
	
	if listed {
		r.logger.Warn("IP blocked by RBL",
			zap.String("client_ip", clientIP),
			zap.String("rbl_server", rblServer),
			zap.String("uri", req.RequestURI),
			zap.String("method", req.Method),
			zap.String("user_agent", req.UserAgent()),
		)
		
		w.Header().Set("X-RBL-Listed", rblServer)
		w.WriteHeader(r.StatusCode)
		fmt.Fprintf(w, "%s (listed in %s)", r.BlockMessage, rblServer)
		return nil
	}
	
	// Log successful check if configured
	if r.LogAllChecks {
		r.logger.Debug("IP passed RBL check",
			zap.String("client_ip", clientIP),
			zap.Strings("rbl_servers", r.Lists),
		)
	}
	
	// IP is clean, continue to next handler
	return next.ServeHTTP(w, req)
}

// checkRBL queries RBL servers to check if an IP is listed
func (r *RBL) checkRBL(ip string) (bool, string) {
	// Reverse the IP address for DNS query
	reversedIP := reverseIP(ip)
	if reversedIP == "" {
		return false, ""
	}
	
	// Check each RBL server
	for _, rblServer := range r.Lists {
		query := fmt.Sprintf("%s.%s", reversedIP, rblServer)
		
		// Perform DNS lookup
		addrs, err := net.LookupHost(query)
		if err == nil && len(addrs) > 0 {
			// IP is listed in this RBL
			return true, rblServer
		}
	}
	
	return false, ""
}

// reverseIP reverses an IPv4 address for RBL DNS queries
func reverseIP(ip string) string {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return ""
	}
	
	// Convert to IPv4
	ipv4 := parsedIP.To4()
	if ipv4 == nil {
		// TODO: Add IPv6 support if needed
		return ""
	}
	
	// Reverse the octets
	return fmt.Sprintf("%d.%d.%d.%d", ipv4[3], ipv4[2], ipv4[1], ipv4[0])
}

// getClientIP extracts the client IP from the request
func getClientIP(req *http.Request) string {
	// Check X-Forwarded-For header
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	
	// Check X-Real-IP header
	if xri := req.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	
	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	
	return ip
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler
func (r *RBL) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "lists":
				r.Lists = d.RemainingArgs()
				if len(r.Lists) == 0 {
					return d.ArgErr()
				}
			case "block_message":
				if !d.NextArg() {
					return d.ArgErr()
				}
				r.BlockMessage = d.Val()
			case "status_code":
				if !d.NextArg() {
					return d.ArgErr()
				}
				var err error
				_, err = fmt.Sscanf(d.Val(), "%d", &r.StatusCode)
				if err != nil {
					return d.Errf("invalid status code: %v", err)
				}
			default:
				return d.Errf("unknown subdirective: %s", d.Val())
			}
		}
	}
	return nil
}

// parseCaddyfile sets up the handler from Caddyfile tokens
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var r RBL
	err := r.UnmarshalCaddyfile(h.Dispenser)
	return r, err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*RBL)(nil)
	_ caddy.Validator             = (*RBL)(nil)
	_ caddyhttp.MiddlewareHandler = (*RBL)(nil)
	_ caddyfile.Unmarshaler       = (*RBL)(nil)
)
