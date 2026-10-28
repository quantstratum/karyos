### Fixed

- The sender's control routes take part in the #838 rule. A control
  route or queue refused for the endpoint's limit (`RouteLimit`,
  `QueueLimit`, `OverCommitted`), or a control route that will not
  close, counts as the data paths' do, so the endpoint's standing reset
  is asked for. An evicted control route whose queue still has frames in
  flight keeps its place in the cache, sends nothing more, and is closed
  again at the sender's next duty before it counts as failed; a burst of
  controls cannot use up that grace. At most `control_routes` routes are
  open and as many closing, within the capacity allocated at creation.
  An ANNOUNCE refused while every cached route is closing waits in order
  and goes at the next send or duty, so every destination gets it: at
  most one waits per destination and publication, a later one replacing
  it in place, within room allocated at creation (`publications` × 16
  per endpoint), so none is dropped. The new `controls_waiting` sender
  counter counts them.
  Any other control refused then is dropped and counted by kind
  (`blocked_status`, `blocked_naks`, `blocked_setup_answers`,
  `blocked_other`): SMs and NAKs are sent again periodically, and a
  SETUP answer is solicited again by its peer. A destination removed,
  or a publication removed, purges the ANNOUNCEs waiting for it. With
  `control_routes = 1`, at most one route is closing: the oldest one is
  given up as failed when another needs to close.
