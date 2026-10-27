# allow_auth_without_tls

{{since('dev')}}

!!! danger
    Take care to apply this ONLY in an appropriate `peer` block, or on a
    listener whose clients you have no way to move to TLS. A credential
    sent before `STARTTLS` crosses the network in the clear.

When set to `true`, the listener advertises and accepts `AUTH` on a session
that has not negotiated TLS. The default is `false`: `AUTH` is offered only
after a successful `STARTTLS` (or on an `ImplicitTls` listener), and a
cleartext attempt is answered with `524 5.7.11`.

The option exists for the submission case where an installed base of
clients authenticates on port 587 without ever issuing `STARTTLS`, and the
operator migrating that service from an MTA that allowed it cannot refuse
them.

```lua
kumo.start_esmtp_listener {
  listen = '0.0.0.0:587',
  peer = {
    ['10.0.0.0/8'] = {
      allow_auth_without_tls = true,
    },
  },
}
```

See also:

 * [smtp_server_auth_plain](../../events/smtp_server_auth_plain.md)
