Wish list and know issues
=========================

- The encryption impacts very negatively in performance, and it is not forward-secret.
  A low penalty alternative with forward secrecy should be used instead.
- Sizes are calculated with ``du``, which is known to produce different results on different
  host even if the copy has been accurate. This is why the size check gives only a warning if it shows
  a difference on source and target hosts. A different, more reliable method could be used, but may take more resources.
- Configurable compression by using other algorithms depending on the data (e.g. lz if compression speed is not
  the limiting factor, etc.)
- Multicast, torrent or other solution should be setup to allow parallel transmission of data to multiple
  hosts in an efficient manner (In progress).
- In general, more flexibility (e.g. level of parallelism, etc.) as long as it uses by default or
  autodetects saner defaults to not increase too much the difficulty of usage.
- Firewall port opening should be optional
- It should also wait until port is fully opened (polling), instead of just waiting 3 seconds
- kill_job function in CuminExecution kill the subprocess in the transferpy running machine.
  Instead, it should kill the actual process in the remote machine.
