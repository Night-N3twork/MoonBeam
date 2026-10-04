;; Bridge between moonbeam's private memory ($host) and one client's shared
;; memory ($client). One instance per attached client. build.rs fills in the
;; @PLACEHOLDERS to produce a memory32 and a memory64 client variant.
;;
;; The client is untrusted: every value read from $client is validated or
;; masked so nothing it writes can make this module trap or touch $host
;; outside the buffers moonbeam passes in.
(module
  (import "host" "memory" (memory $host @HOST_LIMITS))
  (import "client" "memory" (memory $client @CLIENT_LIMITS))

  (global $ready (mut i32) (i32.const 0))
  (global $base (mut @A) (@A.const 0))
  (global $tc (mut @A) (@A.const 0))   ;; to_client ring (moonbeam produces)
  (global $th (mut @A) (@A.const 0))   ;; to_host ring (moonbeam consumes)
  (global $mask (mut i32) (i32.const 0))
  (global $slot_count (mut i32) (i32.const 0))
  (global $slot_size (mut i32) (i32.const 0))
  (global $max_frame (mut i32) (i32.const 0))

  ;; u32 -> client address
  (func $ca (param $x i32) (result @A) @CA_BODY)
  ;; i64 known to be in bounds -> client address
  (func $to_a (param $x i64) (result @A) @TOA_BODY)
  ;; current size of the client memory in bytes
  (func $mem_bytes (result i64) @MEMBYTES_BODY)
  (func $u32_at (param $b i64) (param $off i32) (result i64)
    (i64.extend_i32_u
      (i32.load $client (@A.add (call $to_a (local.get $b)) (call $ca (local.get $off))))))

  (func $slot (param $ring @A) (param $idx i32) (result @A)
    (@A.add
      (@A.add (local.get $ring) (call $ca (i32.const 128)))
      (call $ca (i32.mul (i32.and (local.get $idx) (global.get $mask)) (global.get $slot_size)))))

  ;; bump seq, wake the consumer if it said it was going to sleep
  (func $signal (param $ring @A)
    (drop (i32.atomic.rmw.add $client offset=4 (local.get $ring) (i32.const 1)))
    (if (i32.atomic.rmw.xchg $client offset=8 (local.get $ring) (i32.const 0))
      (then (drop (memory.atomic.notify $client offset=4 (local.get $ring) (i32.const -1))))))

  (func $check_ring (param $r i64) (param $size i64) (param $ring_len i64) (result i32)
    (i32.and
      (i32.and
        (i64.eqz (i64.and (local.get $r) (i64.const 63)))
        (i64.ge_u (local.get $r) (i64.const 64)))
      (i64.le_u (i64.add (local.get $r) (local.get $ring_len)) (local.get $size))))

  ;; Validates the client block at byte offset hi:lo and latches its geometry.
  ;; 0 ok, -1 misaligned, -2 out of bounds, -3 bad magic, -4 bad version,
  ;; -5 bad geometry, -6 bad ring layout, -7 state is not READY, -9 already init
  (func (export "init") (param $lo i32) (param $hi i32) (result i32)
    (local $b i64) (local $mem i64) (local $size i64) (local $sc i64) (local $ss i64)
    (local $mf i64) (local $tc i64) (local $th i64) (local $ring_len i64)
    (if (global.get $ready) (then (return (i32.const -9))))
    (local.set $b (i64.or (i64.extend_i32_u (local.get $lo))
                          (i64.shl (i64.extend_i32_u (local.get $hi)) (i64.const 32))))
    (if (i32.wrap_i64 (i64.and (local.get $b) (i64.const 63))) (then (return (i32.const -1))))
    (local.set $mem (call $mem_bytes))
    (if (i64.gt_u (local.get $b) (local.get $mem)) (then (return (i32.const -2))))
    (if (i64.lt_u (i64.sub (local.get $mem) (local.get $b)) (i64.const 64)) (then (return (i32.const -2))))

    (if (i64.ne (call $u32_at (local.get $b) (i32.const 0)) (i64.const 0x4252424d)) (then (return (i32.const -3))))
    (if (i64.ne (call $u32_at (local.get $b) (i32.const 4)) (i64.const 2)) (then (return (i32.const -4))))

    (local.set $size (call $u32_at (local.get $b) (i32.const 8)))
    (if (i64.gt_u (local.get $size) (i64.sub (local.get $mem) (local.get $b))) (then (return (i32.const -2))))

    (local.set $sc (call $u32_at (local.get $b) (i32.const 12)))
    (local.set $ss (call $u32_at (local.get $b) (i32.const 16)))
    (local.set $mf (call $u32_at (local.get $b) (i32.const 20)))
    (if (i32.or
          (i32.or
            (i64.lt_u (local.get $sc) (i64.const 2))
            (i64.ne (i64.and (local.get $sc) (i64.sub (local.get $sc) (i64.const 1))) (i64.const 0)))
          (i32.or
            (i32.or (i64.lt_u (local.get $mf) (i64.const 60)) (i64.gt_u (local.get $mf) (i64.const 65535)))
            (i32.or
              (i32.or (i64.lt_u (local.get $ss) (i64.add (local.get $mf) (i64.const 4)))
                      (i64.gt_u (local.get $ss) (i64.const 131072)))
              (i64.ne (i64.and (local.get $ss) (i64.const 3)) (i64.const 0)))))
      (then (return (i32.const -5))))

    (local.set $ring_len (i64.add (i64.const 128) (i64.mul (local.get $sc) (local.get $ss))))
    (local.set $tc (call $u32_at (local.get $b) (i32.const 24)))
    (local.set $th (call $u32_at (local.get $b) (i32.const 28)))
    (if (i32.or
          (i32.or
            (i32.eqz (call $check_ring (local.get $tc) (local.get $size) (local.get $ring_len)))
            (i32.eqz (call $check_ring (local.get $th) (local.get $size) (local.get $ring_len))))
          ;; rings must not overlap
          (i32.and (i64.lt_u (local.get $tc) (i64.add (local.get $th) (local.get $ring_len)))
                   (i64.lt_u (local.get $th) (i64.add (local.get $tc) (local.get $ring_len)))))
      (then (return (i32.const -6))))

    (global.set $base (call $to_a (local.get $b)))
    ;; READY (1) -> ATTACHED (2)
    (if (i32.ne (i32.atomic.rmw.cmpxchg $client offset=32 (global.get $base) (i32.const 1) (i32.const 2))
                (i32.const 1))
      (then (return (i32.const -7))))

    (global.set $tc (call $to_a (i64.add (local.get $b) (local.get $tc))))
    (global.set $th (call $to_a (i64.add (local.get $b) (local.get $th))))
    (global.set $slot_count (i32.wrap_i64 (local.get $sc)))
    (global.set $mask (i32.sub (i32.wrap_i64 (local.get $sc)) (i32.const 1)))
    (global.set $slot_size (i32.wrap_i64 (local.get $ss)))
    (global.set $max_frame (i32.wrap_i64 (local.get $mf)))
    (global.set $ready (i32.const 1))
    (i32.const 0))

  ;; Copies host[src..src+len] into the to_client ring.
  ;; 1 queued, 0 dropped (full or too large), -1 not attached
  (func (export "push") (param $src i32) (param $len i32) (result i32)
    (local $head i32) (local $s @A)
    (if (i32.eqz (global.get $ready)) (then (return (i32.const -1))))
    (local.set $head (i32.atomic.load $client (global.get $tc)))
    (if (i32.or
          (i32.gt_u (local.get $len) (global.get $max_frame))
          (i32.ge_u (i32.sub (local.get $head) (i32.atomic.load $client offset=64 (global.get $tc)))
                    (global.get $slot_count)))
      (then
        (drop (i32.atomic.rmw.add $client offset=12 (global.get $tc) (i32.const 1)))
        (return (i32.const 0))))
    (local.set $s (call $slot (global.get $tc) (local.get $head)))
    (i32.store $client (local.get $s) (local.get $len))
    (memory.copy $client $host
      (@A.add (local.get $s) (call $ca (i32.const 4))) (local.get $src) (local.get $len))
    (i32.atomic.store $client (global.get $tc) (i32.add (local.get $head) (i32.const 1)))
    (call $signal (global.get $tc))
    (i32.const 1))

  ;; Consumes up to max_frames slots from the to_host ring, copying valid
  ;; frames into host[dst..dst+cap] as records of u32 len + payload padded to
  ;; 4 bytes. Slots with an invalid length are consumed but not copied.
  ;; Returns slots_consumed << 32 | bytes_written (packed into one i64 because
  ;; Rust's wasm32 C ABI cannot receive multi-value results). Budget callers by
  ;; slots, not records, or a client filling its ring with bad slots can pin
  ;; the caller.
  (func (export "drain") (param $dst i32) (param $cap i32) (param $max_frames i32) (result i64)
    (local $out i32) (local $n i32) (local $head i32) (local $tail i32)
    (local $s @A) (local $len i32) (local $need i32)
    (if (i32.eqz (global.get $ready)) (then (return (i64.const 0))))
    (block $done
      (loop $next
        (br_if $done (i32.ge_u (local.get $n) (local.get $max_frames)))
        (local.set $tail (i32.atomic.load $client offset=64 (global.get $th)))
        (local.set $head (i32.atomic.load $client (global.get $th)))
        (br_if $done (i32.eq (local.get $head) (local.get $tail)))
        (if (i32.gt_u (i32.sub (local.get $head) (local.get $tail)) (global.get $slot_count))
          (then
            ;; corrupt producer index: discard everything outstanding, and
            ;; report the whole budget used so the caller moves on
            (i32.atomic.store $client offset=64 (global.get $th) (local.get $head))
            (local.set $n (local.get $max_frames))
            (br $done)))
        (local.set $s (call $slot (global.get $th) (local.get $tail)))
        (local.set $len (i32.load $client (local.get $s)))
        (if (i32.le_u (local.get $len) (global.get $max_frame))
          (then
            (local.set $need (i32.add (i32.const 4)
              (i32.and (i32.add (local.get $len) (i32.const 3)) (i32.const -4))))
            (br_if $done (i32.gt_u (local.get $need) (i32.sub (local.get $cap) (local.get $out))))
            (i32.store $host (i32.add (local.get $dst) (local.get $out)) (local.get $len))
            (memory.copy $host $client
              (i32.add (i32.add (local.get $dst) (local.get $out)) (i32.const 4))
              (@A.add (local.get $s) (call $ca (i32.const 4)))
              (local.get $len))
            (local.set $out (i32.add (local.get $out) (local.get $need)))))
        (i32.atomic.store $client offset=64 (global.get $th) (i32.add (local.get $tail) (i32.const 1)))
        (local.set $n (i32.add (local.get $n) (i32.const 1)))
        (br $next)))
    (i64.or (i64.shl (i64.extend_i32_u (local.get $n)) (i64.const 32))
            (i64.extend_i32_u (local.get $out))))

  ;; Prepares to sleep on the to_host ring. Returns the seq value to pass to
  ;; Atomics.wait(Async), or -1 if frames are already waiting (drain instead).
  ;; The emptiness check must come after waiting is set: a push that lands
  ;; before it is seen here, one that lands after it will notify.
  (func (export "arm") (result i32)
    (local $seq i32)
    (if (i32.eqz (global.get $ready)) (then (return (i32.const 0))))
    (local.set $seq (i32.atomic.load $client offset=4 (global.get $th)))
    (i32.atomic.store $client offset=8 (global.get $th) (i32.const 1))
    (if (i32.ne (i32.atomic.load $client (global.get $th))              ;; head
                (i32.atomic.load $client offset=64 (global.get $th)))   ;; tail
      (then (return (i32.const -1))))
    (local.get $seq))

  ;; Absolute byte address of the to_host seq word in the client memory.
  (func (export "futex") (result @A)
    (@A.add (global.get $th) (call $ca (i32.const 4))))

  (func (export "state") (result i32)
    (if (i32.eqz (global.get $ready)) (then (return (i32.const 3))))
    (i32.atomic.load $client offset=32 (global.get $base)))

  ;; Stops all access to the client block and marks it RELEASED (3).
  ;; The state store is the last write; after it the client owns the memory.
  (func (export "close")
    (if (i32.eqz (global.get $ready)) (then (return)))
    (global.set $ready (i32.const 0))
    (call $signal (global.get $tc))
    (call $signal (global.get $th))
    (i32.atomic.store $client offset=32 (global.get $base) (i32.const 3))
    (drop (memory.atomic.notify $client offset=4 (global.get $tc) (i32.const -1)))
    (drop (memory.atomic.notify $client offset=4 (global.get $th) (i32.const -1))))
)
