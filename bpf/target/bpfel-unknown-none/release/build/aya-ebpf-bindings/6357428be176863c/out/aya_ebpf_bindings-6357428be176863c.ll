; ModuleID = 'aya_ebpf_bindings.d8309540e951399c-cgu.0'
source_filename = "aya_ebpf_bindings.d8309540e951399c-cgu.0"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

; aya_ebpf_bindings::x86_64::helpers::bpf_d_path
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers10bpf_d_path(ptr noundef %path, ptr noundef %buf, i32 noundef %sz) unnamed_addr #0 !guid !2 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 147 to ptr)(ptr noundef %path, ptr noundef %buf, i32 noundef %sz) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_strtol
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers10bpf_strtol(ptr noundef %buf, i64 noundef %buf_len, i64 noundef %flags, ptr noundef %res) unnamed_addr #0 !guid !3 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 105 to ptr)(ptr noundef %buf, i64 noundef %buf_len, i64 noundef %flags, ptr noundef %res) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_strncmp
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers11bpf_strncmp(ptr noundef %s1, i32 noundef %s1_sz, ptr noundef %s2) unnamed_addr #0 !guid !4 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 182 to ptr)(ptr noundef %s1, i32 noundef %s1_sz, ptr noundef %s2) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_strtoul
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers11bpf_strtoul(ptr noundef %buf, i64 noundef %buf_len, i64 noundef %flags, ptr noundef %res) unnamed_addr #0 !guid !5 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 106 to ptr)(ptr noundef %buf, i64 noundef %buf_len, i64 noundef %flags, ptr noundef %res) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_sys_bpf
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers11bpf_sys_bpf(i32 noundef %cmd, ptr noundef %attr, i32 noundef %attr_size) unnamed_addr #0 !guid !6 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 166 to ptr)(i32 noundef %cmd, ptr noundef %attr, i32 noundef %attr_size) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_find_vma
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers12bpf_find_vma(ptr noundef %task, i64 noundef %addr, ptr noundef %callback_fn, ptr noundef %callback_ctx, i64 noundef %flags) unnamed_addr #0 !guid !7 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 180 to ptr)(ptr noundef %task, i64 noundef %addr, ptr noundef %callback_fn, ptr noundef %callback_ctx, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_redirect
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers12bpf_redirect(i32 noundef %ifindex, i64 noundef %flags) unnamed_addr #0 !guid !8 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 23 to ptr)(i32 noundef %ifindex, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_set_hash
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers12bpf_set_hash(ptr noundef %skb, i32 noundef %hash) unnamed_addr #0 !guid !9 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 48 to ptr)(ptr noundef %skb, i32 noundef %hash) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_snprintf
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers12bpf_snprintf(ptr noundef %str_, i32 noundef %str_size, ptr noundef %fmt, ptr noundef %data, i32 noundef %data_len) unnamed_addr #0 !guid !10 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 165 to ptr)(ptr noundef %str_, i32 noundef %str_size, ptr noundef %fmt, ptr noundef %data, i32 noundef %data_len) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_tcp_sock
; Function Attrs: nounwind
define noundef ptr @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers12bpf_tcp_sock(ptr noundef %sk) unnamed_addr #0 !guid !11 {
start:
  %_0 = tail call noundef ptr inttoptr (i64 96 to ptr)(ptr noundef %sk) #1
  ret ptr %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_check_mtu
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers13bpf_check_mtu(ptr noundef %ctx, i32 noundef %ifindex, ptr noundef %mtu_len, i32 noundef %len_diff, i64 noundef %flags) unnamed_addr #0 !guid !12 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 163 to ptr)(ptr noundef %ctx, i32 noundef %ifindex, ptr noundef %mtu_len, i32 noundef %len_diff, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_csum_diff
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers13bpf_csum_diff(ptr noundef %from, i32 noundef %from_size, ptr noundef %to, i32 noundef %to_size, i32 noundef %seed) unnamed_addr #0 !guid !13 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 28 to ptr)(ptr noundef %from, i32 noundef %from_size, ptr noundef %to, i32 noundef %to_size, i32 noundef %seed) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_get_stack
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers13bpf_get_stack(ptr noundef %ctx, ptr noundef %buf, i32 noundef %size, i64 noundef %flags) unnamed_addr #0 !guid !14 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 67 to ptr)(ptr noundef %ctx, ptr noundef %buf, i32 noundef %size, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_jiffies64
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers13bpf_jiffies64() unnamed_addr #0 !guid !15 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 118 to ptr)() #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_kptr_xchg
; Function Attrs: nounwind
define noundef ptr @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers13bpf_kptr_xchg(ptr noundef %map_value, ptr noundef %ptr) unnamed_addr #0 !guid !16 {
start:
  %_0 = tail call noundef ptr inttoptr (i64 194 to ptr)(ptr noundef %map_value, ptr noundef %ptr) #1
  ret ptr %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_rc_repeat
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers13bpf_rc_repeat(ptr noundef %ctx) unnamed_addr #0 !guid !17 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 77 to ptr)(ptr noundef %ctx) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_seq_write
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers13bpf_seq_write(ptr noundef %m, ptr noundef %data, i32 noundef %len) unnamed_addr #0 !guid !18 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 127 to ptr)(ptr noundef %m, ptr noundef %data, i32 noundef %len) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_sk_assign
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers13bpf_sk_assign(ptr noundef %ctx, ptr noundef %sk, i64 noundef %flags) unnamed_addr #0 !guid !19 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 124 to ptr)(ptr noundef %ctx, ptr noundef %sk, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_spin_lock
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers13bpf_spin_lock(ptr noundef %lock) unnamed_addr #0 !guid !20 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 93 to ptr)(ptr noundef %lock) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_sys_close
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers13bpf_sys_close(i32 noundef %fd) unnamed_addr #0 !guid !21 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 168 to ptr)(i32 noundef %fd) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_tail_call
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers13bpf_tail_call(ptr noundef %ctx, ptr noundef %prog_array_map, i32 noundef %index) unnamed_addr #0 !guid !22 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 12 to ptr)(ptr noundef %ctx, ptr noundef %prog_array_map, i32 noundef %index) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_csum_level
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers14bpf_csum_level(ptr noundef %skb, i64 noundef %level) unnamed_addr #0 !guid !23 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 135 to ptr)(ptr noundef %skb, i64 noundef %level) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_fib_lookup
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers14bpf_fib_lookup(ptr noundef %ctx, ptr noundef %params, i32 noundef %plen, i32 noundef %flags) unnamed_addr #0 !guid !24 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 69 to ptr)(ptr noundef %ctx, ptr noundef %params, i32 noundef %plen, i32 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_get_retval
; Function Attrs: nounwind
define noundef i32 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers14bpf_get_retval() unnamed_addr #0 !guid !25 {
start:
  %_0 = tail call noundef i32 inttoptr (i64 186 to ptr)() #1
  ret i32 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_getsockopt
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers14bpf_getsockopt(ptr noundef %bpf_socket, i32 noundef %level, i32 noundef %optname, ptr noundef %optval, i32 noundef %optlen) unnamed_addr #0 !guid !26 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 57 to ptr)(ptr noundef %bpf_socket, i32 noundef %level, i32 noundef %optname, ptr noundef %optval, i32 noundef %optlen) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_probe_read
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers14bpf_probe_read(ptr noundef %dst, i32 noundef %size, ptr noundef %unsafe_ptr) unnamed_addr #0 !guid !27 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 4 to ptr)(ptr noundef %dst, i32 noundef %size, ptr noundef %unsafe_ptr) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_rc_keydown
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers14bpf_rc_keydown(ptr noundef %ctx, i32 noundef %protocol, i64 noundef %scancode, i32 noundef %toggle) unnamed_addr #0 !guid !28 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 78 to ptr)(ptr noundef %ctx, i32 noundef %protocol, i64 noundef %scancode, i32 noundef %toggle) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_seq_printf
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers14bpf_seq_printf(ptr noundef %m, ptr noundef %fmt, i32 noundef %fmt_size, ptr noundef %data, i32 noundef %data_len) unnamed_addr #0 !guid !29 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 126 to ptr)(ptr noundef %m, ptr noundef %fmt, i32 noundef %fmt_size, ptr noundef %data, i32 noundef %data_len) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_set_retval
; Function Attrs: nounwind
define noundef i32 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers14bpf_set_retval(i32 noundef %retval) unnamed_addr #0 !guid !30 {
start:
  %_0 = tail call noundef i32 inttoptr (i64 187 to ptr)(i32 noundef %retval) #1
  ret i32 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_setsockopt
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers14bpf_setsockopt(ptr noundef %bpf_socket, i32 noundef %level, i32 noundef %optname, ptr noundef %optval, i32 noundef %optlen) unnamed_addr #0 !guid !31 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 49 to ptr)(ptr noundef %bpf_socket, i32 noundef %level, i32 noundef %optname, ptr noundef %optval, i32 noundef %optlen) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_sk_release
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers14bpf_sk_release(ptr noundef %sock) unnamed_addr #0 !guid !32 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 86 to ptr)(ptr noundef %sock) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_skb_output
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers14bpf_skb_output(ptr noundef %ctx, ptr noundef %map, i64 noundef %flags, ptr noundef %data, i64 noundef %size) unnamed_addr #0 !guid !33 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 111 to ptr)(ptr noundef %ctx, ptr noundef %map, i64 noundef %flags, ptr noundef %data, i64 noundef %size) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_timer_init
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers14bpf_timer_init(ptr noundef %timer, ptr noundef %map, i64 noundef %flags) unnamed_addr #0 !guid !34 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 169 to ptr)(ptr noundef %timer, ptr noundef %map, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_xdp_output
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers14bpf_xdp_output(ptr noundef %ctx, ptr noundef %map, i64 noundef %flags, ptr noundef %data, i64 noundef %size) unnamed_addr #0 !guid !35 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 121 to ptr)(ptr noundef %ctx, ptr noundef %map, i64 noundef %flags, ptr noundef %data, i64 noundef %size) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_csum_update
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers15bpf_csum_update(ptr noundef %skb, i32 noundef %csum) unnamed_addr #0 !guid !36 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 40 to ptr)(ptr noundef %skb, i32 noundef %csum) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_dynptr_data
; Function Attrs: nounwind
define noundef ptr @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers15bpf_dynptr_data(ptr noundef %ptr, i32 noundef %offset, i32 noundef %len) unnamed_addr #0 !guid !37 {
start:
  %_0 = tail call noundef ptr inttoptr (i64 203 to ptr)(ptr noundef %ptr, i32 noundef %offset, i32 noundef %len) #1
  ret ptr %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_dynptr_read
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers15bpf_dynptr_read(ptr noundef %dst, i32 noundef %len, ptr noundef %src, i32 noundef %offset, i64 noundef %flags) unnamed_addr #0 !guid !38 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 201 to ptr)(ptr noundef %dst, i32 noundef %len, ptr noundef %src, i32 noundef %offset, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_get_func_ip
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers15bpf_get_func_ip(ptr noundef %ctx) unnamed_addr #0 !guid !39 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 173 to ptr)(ptr noundef %ctx) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_get_stackid
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers15bpf_get_stackid(ptr noundef %ctx, ptr noundef %map, i64 noundef %flags) unnamed_addr #0 !guid !40 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 27 to ptr)(ptr noundef %ctx, ptr noundef %map, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_per_cpu_ptr
; Function Attrs: nounwind
define noundef ptr @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers15bpf_per_cpu_ptr(ptr noundef %percpu_ptr, i32 noundef %cpu) unnamed_addr #0 !guid !41 {
start:
  %_0 = tail call noundef ptr inttoptr (i64 153 to ptr)(ptr noundef %percpu_ptr, i32 noundef %cpu) #1
  ret ptr %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_send_signal
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers15bpf_send_signal(i32 noundef %sig) unnamed_addr #0 !guid !42 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 109 to ptr)(i32 noundef %sig) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_sk_fullsock
; Function Attrs: nounwind
define noundef ptr @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers15bpf_sk_fullsock(ptr noundef %sk) unnamed_addr #0 !guid !43 {
start:
  %_0 = tail call noundef ptr inttoptr (i64 95 to ptr)(ptr noundef %sk) #1
  ret ptr %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_spin_unlock
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers15bpf_spin_unlock(ptr noundef %lock) unnamed_addr #0 !guid !44 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 94 to ptr)(ptr noundef %lock) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_timer_start
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers15bpf_timer_start(ptr noundef %timer, i64 noundef %nsecs, i64 noundef %flags) unnamed_addr #0 !guid !45 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 171 to ptr)(ptr noundef %timer, i64 noundef %nsecs, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_dynptr_write
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers16bpf_dynptr_write(ptr noundef %dst, i32 noundef %offset, ptr noundef %src, i32 noundef %len, i64 noundef %flags) unnamed_addr #0 !guid !46 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 202 to ptr)(ptr noundef %dst, i32 noundef %offset, ptr noundef %src, i32 noundef %len, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_get_func_arg
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers16bpf_get_func_arg(ptr noundef %ctx, i32 noundef %n, ptr noundef %value) unnamed_addr #0 !guid !47 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 183 to ptr)(ptr noundef %ctx, i32 noundef %n, ptr noundef %value) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_get_func_ret
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers16bpf_get_func_ret(ptr noundef %ctx, ptr noundef %value) unnamed_addr #0 !guid !48 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 184 to ptr)(ptr noundef %ctx, ptr noundef %value) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_ktime_get_ns
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers16bpf_ktime_get_ns() unnamed_addr #0 !guid !49 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 5 to ptr)() #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_load_hdr_opt
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers16bpf_load_hdr_opt(ptr noundef %skops, ptr noundef %searchby_res, i32 noundef %len, i64 noundef %flags) unnamed_addr #0 !guid !50 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 142 to ptr)(ptr noundef %skops, ptr noundef %searchby_res, i32 noundef %len, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_map_pop_elem
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers16bpf_map_pop_elem(ptr noundef %map, ptr noundef %value) unnamed_addr #0 !guid !51 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 88 to ptr)(ptr noundef %map, ptr noundef %value) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_msg_pop_data
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers16bpf_msg_pop_data(ptr noundef %msg, i32 noundef %start1, i32 noundef %len, i64 noundef %flags) unnamed_addr #0 !guid !52 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 91 to ptr)(ptr noundef %msg, i32 noundef %start1, i32 noundef %len, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_redirect_map
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers16bpf_redirect_map(ptr noundef %map, i64 noundef %key, i64 noundef %flags) unnamed_addr #0 !guid !53 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 51 to ptr)(ptr noundef %map, i64 noundef %key, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_sk_cgroup_id
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers16bpf_sk_cgroup_id(ptr noundef %sk) unnamed_addr #0 !guid !54 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 128 to ptr)(ptr noundef %sk) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_skb_vlan_pop
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers16bpf_skb_vlan_pop(ptr noundef %skb) unnamed_addr #0 !guid !55 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 19 to ptr)(ptr noundef %skb) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_snprintf_btf
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers16bpf_snprintf_btf(ptr noundef %str_, i32 noundef %str_size, ptr noundef %ptr, i32 noundef %btf_ptr_size, i64 noundef %flags) unnamed_addr #0 !guid !56 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 149 to ptr)(ptr noundef %str_, i32 noundef %str_size, ptr noundef %ptr, i32 noundef %btf_ptr_size, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_task_pt_regs
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers16bpf_task_pt_regs(ptr noundef %task) unnamed_addr #0 !guid !57 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 175 to ptr)(ptr noundef %task) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_tcp_send_ack
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers16bpf_tcp_send_ack(ptr noundef %tp, i32 noundef %rcv_nxt) unnamed_addr #0 !guid !58 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 116 to ptr)(ptr noundef %tp, i32 noundef %rcv_nxt) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_this_cpu_ptr
; Function Attrs: nounwind
define noundef ptr @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers16bpf_this_cpu_ptr(ptr noundef %percpu_ptr) unnamed_addr #0 !guid !59 {
start:
  %_0 = tail call noundef ptr inttoptr (i64 154 to ptr)(ptr noundef %percpu_ptr) #1
  ret ptr %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_timer_cancel
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers16bpf_timer_cancel(ptr noundef %timer) unnamed_addr #0 !guid !60 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 172 to ptr)(ptr noundef %timer) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_bprm_opts_set
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers17bpf_bprm_opts_set(ptr noundef %bprm, i64 noundef %flags) unnamed_addr #0 !guid !61 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 159 to ptr)(ptr noundef %bprm, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_ima_file_hash
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers17bpf_ima_file_hash(ptr noundef %file, ptr noundef %dst, i32 noundef %size) unnamed_addr #0 !guid !62 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 193 to ptr)(ptr noundef %file, ptr noundef %dst, i32 noundef %size) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_map_peek_elem
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers17bpf_map_peek_elem(ptr noundef %map, ptr noundef %value) unnamed_addr #0 !guid !63 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 89 to ptr)(ptr noundef %map, ptr noundef %value) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_map_push_elem
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers17bpf_map_push_elem(ptr noundef %map, ptr noundef %value, i64 noundef %flags) unnamed_addr #0 !guid !64 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 87 to ptr)(ptr noundef %map, ptr noundef %value, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_msg_pull_data
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers17bpf_msg_pull_data(ptr noundef %msg, i32 noundef %start1, i32 noundef %end, i64 noundef %flags) unnamed_addr #0 !guid !65 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 63 to ptr)(ptr noundef %msg, i32 noundef %start1, i32 noundef %end, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_msg_push_data
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers17bpf_msg_push_data(ptr noundef %msg, i32 noundef %start1, i32 noundef %len, i64 noundef %flags) unnamed_addr #0 !guid !66 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 90 to ptr)(ptr noundef %msg, i32 noundef %start1, i32 noundef %len, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_redirect_peer
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers17bpf_redirect_peer(i32 noundef %ifindex, i64 noundef %flags) unnamed_addr #0 !guid !67 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 155 to ptr)(i32 noundef %ifindex, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_ringbuf_query
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers17bpf_ringbuf_query(ptr noundef %ringbuf, i64 noundef %flags) unnamed_addr #0 !guid !68 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 134 to ptr)(ptr noundef %ringbuf, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_sk_lookup_tcp
; Function Attrs: nounwind
define noundef ptr @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers17bpf_sk_lookup_tcp(ptr noundef %ctx, ptr noundef %tuple, i32 noundef %tuple_size, i64 noundef %netns, i64 noundef %flags) unnamed_addr #0 !guid !69 {
start:
  %_0 = tail call noundef ptr inttoptr (i64 84 to ptr)(ptr noundef %ctx, ptr noundef %tuple, i32 noundef %tuple_size, i64 noundef %netns, i64 noundef %flags) #1
  ret ptr %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_sk_lookup_udp
; Function Attrs: nounwind
define noundef ptr @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers17bpf_sk_lookup_udp(ptr noundef %ctx, ptr noundef %tuple, i32 noundef %tuple_size, i64 noundef %netns, i64 noundef %flags) unnamed_addr #0 !guid !70 {
start:
  %_0 = tail call noundef ptr inttoptr (i64 85 to ptr)(ptr noundef %ctx, ptr noundef %tuple, i32 noundef %tuple_size, i64 noundef %netns, i64 noundef %flags) #1
  ret ptr %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_skb_cgroup_id
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers17bpf_skb_cgroup_id(ptr noundef %skb) unnamed_addr #0 !guid !71 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 79 to ptr)(ptr noundef %skb) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_skb_pull_data
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers17bpf_skb_pull_data(ptr noundef %skb, i32 noundef %len) unnamed_addr #0 !guid !72 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 39 to ptr)(ptr noundef %skb, i32 noundef %len) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_skb_vlan_push
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers17bpf_skb_vlan_push(ptr noundef %skb, i16 noundef %vlan_proto, i16 noundef %vlan_tci) unnamed_addr #0 !guid !73 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 18 to ptr)(ptr noundef %skb, i16 noundef zeroext %vlan_proto, i16 noundef zeroext %vlan_tci) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_store_hdr_opt
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers17bpf_store_hdr_opt(ptr noundef %skops, ptr noundef %from, i32 noundef %len, i64 noundef %flags) unnamed_addr #0 !guid !74 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 143 to ptr)(ptr noundef %skops, ptr noundef %from, i32 noundef %len, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_trace_vprintk
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers17bpf_trace_vprintk(ptr noundef %fmt, i32 noundef %fmt_size, ptr noundef %data, i32 noundef %data_len) unnamed_addr #0 !guid !75 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 177 to ptr)(ptr noundef %fmt, i32 noundef %fmt_size, ptr noundef %data, i32 noundef %data_len) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_clone_redirect
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers18bpf_clone_redirect(ptr noundef %skb, i32 noundef %ifindex, i64 noundef %flags) unnamed_addr #0 !guid !76 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 13 to ptr)(ptr noundef %skb, i32 noundef %ifindex, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_copy_from_user
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers18bpf_copy_from_user(ptr noundef %dst, i32 noundef %size, ptr noundef %user_ptr) unnamed_addr #0 !guid !77 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 148 to ptr)(ptr noundef %dst, i32 noundef %size, ptr noundef %user_ptr) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_get_socket_uid
; Function Attrs: nounwind
define noundef i32 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers18bpf_get_socket_uid(ptr noundef %skb) unnamed_addr #0 !guid !78 {
start:
  %_0 = tail call noundef i32 inttoptr (i64 47 to ptr)(ptr noundef %skb) #1
  ret i32 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_get_task_stack
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers18bpf_get_task_stack(ptr noundef %task, ptr noundef %buf, i32 noundef %size, i64 noundef %flags) unnamed_addr #0 !guid !79 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 141 to ptr)(ptr noundef %task, ptr noundef %buf, i32 noundef %size, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_ima_inode_hash
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers18bpf_ima_inode_hash(ptr noundef %inode, ptr noundef %dst, i32 noundef %size) unnamed_addr #0 !guid !80 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 161 to ptr)(ptr noundef %inode, ptr noundef %dst, i32 noundef %size) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_lwt_push_encap
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers18bpf_lwt_push_encap(ptr noundef %skb, i32 noundef %type_, ptr noundef %hdr, i32 noundef %len) unnamed_addr #0 !guid !81 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 73 to ptr)(ptr noundef %skb, i32 noundef %type_, ptr noundef %hdr, i32 noundef %len) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_msg_cork_bytes
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers18bpf_msg_cork_bytes(ptr noundef %msg, i32 noundef %bytes) unnamed_addr #0 !guid !82 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 62 to ptr)(ptr noundef %msg, i32 noundef %bytes) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_probe_read_str
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers18bpf_probe_read_str(ptr noundef %dst, i32 noundef %size, ptr noundef %unsafe_ptr) unnamed_addr #0 !guid !83 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 45 to ptr)(ptr noundef %dst, i32 noundef %size, ptr noundef %unsafe_ptr) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_rc_pointer_rel
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers18bpf_rc_pointer_rel(ptr noundef %ctx, i32 noundef %rel_x, i32 noundef %rel_y) unnamed_addr #0 !guid !84 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 92 to ptr)(ptr noundef %ctx, i32 noundef %rel_x, i32 noundef %rel_y) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_redirect_neigh
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers18bpf_redirect_neigh(i32 noundef %ifindex, ptr noundef %params, i32 noundef %plen, i64 noundef %flags) unnamed_addr #0 !guid !85 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 152 to ptr)(i32 noundef %ifindex, ptr noundef %params, i32 noundef %plen, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_ringbuf_output
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers18bpf_ringbuf_output(ptr noundef %ringbuf, ptr noundef %data, i64 noundef %size, i64 noundef %flags) unnamed_addr #0 !guid !86 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 130 to ptr)(ptr noundef %ringbuf, ptr noundef %data, i64 noundef %size, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_ringbuf_submit
; Function Attrs: nounwind
define void @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers18bpf_ringbuf_submit(ptr noundef %data, i64 noundef %flags) unnamed_addr #0 !guid !87 {
start:
  tail call void inttoptr (i64 132 to ptr)(ptr noundef %data, i64 noundef %flags) #1
  ret void
}

; aya_ebpf_bindings::x86_64::helpers::bpf_seq_printf_btf
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers18bpf_seq_printf_btf(ptr noundef %m, ptr noundef %ptr, i32 noundef %ptr_size, i64 noundef %flags) unnamed_addr #0 !guid !88 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 150 to ptr)(ptr noundef %m, ptr noundef %ptr, i32 noundef %ptr_size, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_sk_storage_get
; Function Attrs: nounwind
define noundef ptr @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers18bpf_sk_storage_get(ptr noundef %map, ptr noundef %sk, ptr noundef %value, i64 noundef %flags) unnamed_addr #0 !guid !89 {
start:
  %_0 = tail call noundef ptr inttoptr (i64 107 to ptr)(ptr noundef %map, ptr noundef %sk, ptr noundef %value, i64 noundef %flags) #1
  ret ptr %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_skb_ecn_set_ce
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers18bpf_skb_ecn_set_ce(ptr noundef %skb) unnamed_addr #0 !guid !90 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 97 to ptr)(ptr noundef %skb) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_skb_load_bytes
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers18bpf_skb_load_bytes(ptr noundef %skb, i32 noundef %offset, ptr noundef %to, i32 noundef %len) unnamed_addr #0 !guid !91 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 26 to ptr)(ptr noundef %skb, i32 noundef %offset, ptr noundef %to, i32 noundef %len) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_skb_set_tstamp
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers18bpf_skb_set_tstamp(ptr noundef %skb, i64 noundef %tstamp, i32 noundef %tstamp_type) unnamed_addr #0 !guid !92 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 192 to ptr)(ptr noundef %skb, i64 noundef %tstamp, i32 noundef %tstamp_type) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_skc_lookup_tcp
; Function Attrs: nounwind
define noundef ptr @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers18bpf_skc_lookup_tcp(ptr noundef %ctx, ptr noundef %tuple, i32 noundef %tuple_size, i64 noundef %netns, i64 noundef %flags) unnamed_addr #0 !guid !93 {
start:
  %_0 = tail call noundef ptr inttoptr (i64 99 to ptr)(ptr noundef %ctx, ptr noundef %tuple, i32 noundef %tuple_size, i64 noundef %netns, i64 noundef %flags) #1
  ret ptr %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_sock_from_file
; Function Attrs: nounwind
define noundef ptr @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers18bpf_sock_from_file(ptr noundef %file) unnamed_addr #0 !guid !94 {
start:
  %_0 = tail call noundef ptr inttoptr (i64 162 to ptr)(ptr noundef %file) #1
  ret ptr %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_xdp_load_bytes
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers18bpf_xdp_load_bytes(ptr noundef %xdp_md, i32 noundef %offset, ptr noundef %buf, i32 noundef %len) unnamed_addr #0 !guid !95 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 189 to ptr)(ptr noundef %xdp_md, i32 noundef %offset, ptr noundef %buf, i32 noundef %len) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_dynptr_from_mem
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_dynptr_from_mem(ptr noundef %data, i32 noundef %size, i64 noundef %flags, ptr noundef %ptr) unnamed_addr #0 !guid !96 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 197 to ptr)(ptr noundef %data, i32 noundef %size, i64 noundef %flags, ptr noundef %ptr) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_get_hash_recalc
; Function Attrs: nounwind
define noundef i32 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_get_hash_recalc(ptr noundef %skb) unnamed_addr #0 !guid !97 {
start:
  %_0 = tail call noundef i32 inttoptr (i64 34 to ptr)(ptr noundef %skb) #1
  ret i32 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_get_prandom_u32
; Function Attrs: nounwind
define noundef i32 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_get_prandom_u32() unnamed_addr #0 !guid !98 {
start:
  %_0 = tail call noundef i32 inttoptr (i64 7 to ptr)() #1
  ret i32 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_get_route_realm
; Function Attrs: nounwind
define noundef i32 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_get_route_realm(ptr noundef %skb) unnamed_addr #0 !guid !99 {
start:
  %_0 = tail call noundef i32 inttoptr (i64 24 to ptr)(ptr noundef %skb) #1
  ret i32 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_l3_csum_replace
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_l3_csum_replace(ptr noundef %skb, i32 noundef %offset, i64 noundef %from, i64 noundef %to, i64 noundef %size) unnamed_addr #0 !guid !100 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 10 to ptr)(ptr noundef %skb, i32 noundef %offset, i64 noundef %from, i64 noundef %to, i64 noundef %size) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_l4_csum_replace
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_l4_csum_replace(ptr noundef %skb, i32 noundef %offset, i64 noundef %from, i64 noundef %to, i64 noundef %flags) unnamed_addr #0 !guid !101 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 11 to ptr)(ptr noundef %skb, i32 noundef %offset, i64 noundef %from, i64 noundef %to, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_lwt_seg6_action
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_lwt_seg6_action(ptr noundef %skb, i32 noundef %action, ptr noundef %param, i32 noundef %param_len) unnamed_addr #0 !guid !102 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 76 to ptr)(ptr noundef %skb, i32 noundef %action, ptr noundef %param, i32 noundef %param_len) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_map_delete_elem
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_map_delete_elem(ptr noundef %map, ptr noundef %key) unnamed_addr #0 !guid !103 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 3 to ptr)(ptr noundef %map, ptr noundef %key) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_map_lookup_elem
; Function Attrs: nounwind
define noundef ptr @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_map_lookup_elem(ptr noundef %map, ptr noundef %key) unnamed_addr #0 !guid !104 {
start:
  %_0 = tail call noundef ptr inttoptr (i64 1 to ptr)(ptr noundef %map, ptr noundef %key) #1
  ret ptr %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_map_update_elem
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_map_update_elem(ptr noundef %map, ptr noundef %key, ptr noundef %value, i64 noundef %flags) unnamed_addr #0 !guid !105 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 2 to ptr)(ptr noundef %map, ptr noundef %key, ptr noundef %value, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_msg_apply_bytes
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_msg_apply_bytes(ptr noundef %msg, i32 noundef %bytes) unnamed_addr #0 !guid !106 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 61 to ptr)(ptr noundef %msg, i32 noundef %bytes) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_override_return
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_override_return(ptr noundef %regs, i64 noundef %rc) unnamed_addr #0 !guid !107 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 58 to ptr)(ptr noundef %regs, i64 noundef %rc) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_perf_event_read
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_perf_event_read(ptr noundef %map, i64 noundef %flags) unnamed_addr #0 !guid !108 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 22 to ptr)(ptr noundef %map, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_probe_read_user
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_probe_read_user(ptr noundef %dst, i32 noundef %size, ptr noundef %unsafe_ptr) unnamed_addr #0 !guid !109 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 112 to ptr)(ptr noundef %dst, i32 noundef %size, ptr noundef %unsafe_ptr) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_reserve_hdr_opt
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_reserve_hdr_opt(ptr noundef %skops, i32 noundef %len, i64 noundef %flags) unnamed_addr #0 !guid !110 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 144 to ptr)(ptr noundef %skops, i32 noundef %len, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_ringbuf_discard
; Function Attrs: nounwind
define void @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_ringbuf_discard(ptr noundef %data, i64 noundef %flags) unnamed_addr #0 !guid !111 {
start:
  tail call void inttoptr (i64 133 to ptr)(ptr noundef %data, i64 noundef %flags) #1
  ret void
}

; aya_ebpf_bindings::x86_64::helpers::bpf_ringbuf_reserve
; Function Attrs: nounwind
define noundef ptr @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_ringbuf_reserve(ptr noundef %ringbuf, i64 noundef %size, i64 noundef %flags) unnamed_addr #0 !guid !112 {
start:
  %_0 = tail call noundef ptr inttoptr (i64 131 to ptr)(ptr noundef %ringbuf, i64 noundef %size, i64 noundef %flags) #1
  ret ptr %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_sk_redirect_map
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_sk_redirect_map(ptr noundef %skb, ptr noundef %map, i32 noundef %key, i64 noundef %flags) unnamed_addr #0 !guid !113 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 52 to ptr)(ptr noundef %skb, ptr noundef %map, i32 noundef %key, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_skb_adjust_room
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_skb_adjust_room(ptr noundef %skb, i32 noundef %len_diff, i32 noundef %mode, i64 noundef %flags) unnamed_addr #0 !guid !114 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 50 to ptr)(ptr noundef %skb, i32 noundef %len_diff, i32 noundef %mode, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_skb_change_head
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_skb_change_head(ptr noundef %skb, i32 noundef %len, i64 noundef %flags) unnamed_addr #0 !guid !115 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 43 to ptr)(ptr noundef %skb, i32 noundef %len, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_skb_change_tail
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_skb_change_tail(ptr noundef %skb, i32 noundef %len, i64 noundef %flags) unnamed_addr #0 !guid !116 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 38 to ptr)(ptr noundef %skb, i32 noundef %len, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_skb_change_type
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_skb_change_type(ptr noundef %skb, i32 noundef %type_) unnamed_addr #0 !guid !117 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 32 to ptr)(ptr noundef %skb, i32 noundef %type_) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_skb_store_bytes
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_skb_store_bytes(ptr noundef %skb, i32 noundef %offset, ptr noundef %from, i32 noundef %len, i64 noundef %flags) unnamed_addr #0 !guid !118 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 9 to ptr)(ptr noundef %skb, i32 noundef %offset, ptr noundef %from, i32 noundef %len, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_skc_to_tcp_sock
; Function Attrs: nounwind
define noundef ptr @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_skc_to_tcp_sock(ptr noundef %sk) unnamed_addr #0 !guid !119 {
start:
  %_0 = tail call noundef ptr inttoptr (i64 137 to ptr)(ptr noundef %sk) #1
  ret ptr %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_sock_map_update
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_sock_map_update(ptr noundef %skops, ptr noundef %map, ptr noundef %key, i64 noundef %flags) unnamed_addr #0 !guid !120 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 53 to ptr)(ptr noundef %skops, ptr noundef %map, ptr noundef %key, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_sysctl_get_name
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_sysctl_get_name(ptr noundef %ctx, ptr noundef %buf, i64 noundef %buf_len, i64 noundef %flags) unnamed_addr #0 !guid !121 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 101 to ptr)(ptr noundef %ctx, ptr noundef %buf, i64 noundef %buf_len, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_xdp_adjust_head
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_xdp_adjust_head(ptr noundef %xdp_md, i32 noundef %delta) unnamed_addr #0 !guid !122 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 44 to ptr)(ptr noundef %xdp_md, i32 noundef %delta) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_xdp_adjust_meta
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_xdp_adjust_meta(ptr noundef %xdp_md, i32 noundef %delta) unnamed_addr #0 !guid !123 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 54 to ptr)(ptr noundef %xdp_md, i32 noundef %delta) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_xdp_adjust_tail
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_xdp_adjust_tail(ptr noundef %xdp_md, i32 noundef %delta) unnamed_addr #0 !guid !124 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 65 to ptr)(ptr noundef %xdp_md, i32 noundef %delta) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_xdp_store_bytes
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_xdp_store_bytes(ptr noundef %xdp_md, i32 noundef %offset, ptr noundef %buf, i32 noundef %len) unnamed_addr #0 !guid !125 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 190 to ptr)(ptr noundef %xdp_md, i32 noundef %offset, ptr noundef %buf, i32 noundef %len) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_cgrp_storage_get
; Function Attrs: nounwind
define noundef ptr @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers20bpf_cgrp_storage_get(ptr noundef %map, ptr noundef %cgroup, ptr noundef %value, i64 noundef %flags) unnamed_addr #0 !guid !126 {
start:
  %_0 = tail call noundef ptr inttoptr (i64 210 to ptr)(ptr noundef %map, ptr noundef %cgroup, ptr noundef %value, i64 noundef %flags) #1
  ret ptr %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_get_current_comm
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers20bpf_get_current_comm(ptr noundef %buf, i32 noundef %size_of_buf) unnamed_addr #0 !guid !127 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 16 to ptr)(ptr noundef %buf, i32 noundef %size_of_buf) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_get_current_task
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers20bpf_get_current_task() unnamed_addr #0 !guid !128 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 35 to ptr)() #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_get_func_arg_cnt
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers20bpf_get_func_arg_cnt(ptr noundef %ctx) unnamed_addr #0 !guid !129 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 185 to ptr)(ptr noundef %ctx) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_get_netns_cookie
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers20bpf_get_netns_cookie(ptr noundef %ctx) unnamed_addr #0 !guid !130 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 122 to ptr)(ptr noundef %ctx) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_get_numa_node_id
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers20bpf_get_numa_node_id() unnamed_addr #0 !guid !131 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 42 to ptr)() #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_ktime_get_tai_ns
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers20bpf_ktime_get_tai_ns() unnamed_addr #0 !guid !132 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 208 to ptr)() #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_msg_redirect_map
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers20bpf_msg_redirect_map(ptr noundef %msg, ptr noundef %map, i32 noundef %key, i64 noundef %flags) unnamed_addr #0 !guid !133 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 60 to ptr)(ptr noundef %msg, ptr noundef %map, i32 noundef %key, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_probe_write_user
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers20bpf_probe_write_user(ptr noundef %dst, ptr noundef %src, i32 noundef %len) unnamed_addr #0 !guid !134 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 36 to ptr)(ptr noundef %dst, ptr noundef %src, i32 noundef %len) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_set_hash_invalid
; Function Attrs: nounwind
define void @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers20bpf_set_hash_invalid(ptr noundef %skb) unnamed_addr #0 !guid !135 {
start:
  tail call void inttoptr (i64 41 to ptr)(ptr noundef %skb) #1
  ret void
}

; aya_ebpf_bindings::x86_64::helpers::bpf_sk_redirect_hash
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers20bpf_sk_redirect_hash(ptr noundef %skb, ptr noundef %map, ptr noundef %key, i64 noundef %flags) unnamed_addr #0 !guid !136 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 72 to ptr)(ptr noundef %skb, ptr noundef %map, ptr noundef %key, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_skb_change_proto
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers20bpf_skb_change_proto(ptr noundef %skb, i16 noundef %proto, i64 noundef %flags) unnamed_addr #0 !guid !137 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 31 to ptr)(ptr noundef %skb, i16 noundef zeroext %proto, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_skb_under_cgroup
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers20bpf_skb_under_cgroup(ptr noundef %skb, ptr noundef %map, i32 noundef %index) unnamed_addr #0 !guid !138 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 33 to ptr)(ptr noundef %skb, ptr noundef %map, i32 noundef %index) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_skc_to_tcp6_sock
; Function Attrs: nounwind
define noundef ptr @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers20bpf_skc_to_tcp6_sock(ptr noundef %sk) unnamed_addr #0 !guid !139 {
start:
  %_0 = tail call noundef ptr inttoptr (i64 136 to ptr)(ptr noundef %sk) #1
  ret ptr %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_skc_to_udp6_sock
; Function Attrs: nounwind
define noundef ptr @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers20bpf_skc_to_udp6_sock(ptr noundef %sk) unnamed_addr #0 !guid !140 {
start:
  %_0 = tail call noundef ptr inttoptr (i64 140 to ptr)(ptr noundef %sk) #1
  ret ptr %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_skc_to_unix_sock
; Function Attrs: nounwind
define noundef ptr @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers20bpf_skc_to_unix_sock(ptr noundef %sk) unnamed_addr #0 !guid !141 {
start:
  %_0 = tail call noundef ptr inttoptr (i64 178 to ptr)(ptr noundef %sk) #1
  ret ptr %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_sock_hash_update
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers20bpf_sock_hash_update(ptr noundef %skops, ptr noundef %map, ptr noundef %key, i64 noundef %flags) unnamed_addr #0 !guid !142 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 70 to ptr)(ptr noundef %skops, ptr noundef %map, ptr noundef %key, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_task_storage_get
; Function Attrs: nounwind
define noundef ptr @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers20bpf_task_storage_get(ptr noundef %map, ptr noundef %task, ptr noundef %value, i64 noundef %flags) unnamed_addr #0 !guid !143 {
start:
  %_0 = tail call noundef ptr inttoptr (i64 156 to ptr)(ptr noundef %map, ptr noundef %task, ptr noundef %value, i64 noundef %flags) #1
  ret ptr %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_xdp_get_buff_len
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers20bpf_xdp_get_buff_len(ptr noundef %xdp_md) unnamed_addr #0 !guid !144 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 188 to ptr)(ptr noundef %xdp_md) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_for_each_map_elem
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers21bpf_for_each_map_elem(ptr noundef %map, ptr noundef %callback_fn, ptr noundef %callback_ctx, i64 noundef %flags) unnamed_addr #0 !guid !145 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 164 to ptr)(ptr noundef %map, ptr noundef %callback_fn, ptr noundef %callback_ctx, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_get_attach_cookie
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers21bpf_get_attach_cookie(ptr noundef %ctx) unnamed_addr #0 !guid !146 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 174 to ptr)(ptr noundef %ctx) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_get_listener_sock
; Function Attrs: nounwind
define noundef ptr @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers21bpf_get_listener_sock(ptr noundef %sk) unnamed_addr #0 !guid !147 {
start:
  %_0 = tail call noundef ptr inttoptr (i64 98 to ptr)(ptr noundef %sk) #1
  ret ptr %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_get_local_storage
; Function Attrs: nounwind
define noundef ptr @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers21bpf_get_local_storage(ptr noundef %map, i64 noundef %flags) unnamed_addr #0 !guid !148 {
start:
  %_0 = tail call noundef ptr inttoptr (i64 81 to ptr)(ptr noundef %map, i64 noundef %flags) #1
  ret ptr %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_get_socket_cookie
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers21bpf_get_socket_cookie(ptr noundef %ctx) unnamed_addr #0 !guid !149 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 46 to ptr)(ptr noundef %ctx) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_inode_storage_get
; Function Attrs: nounwind
define noundef ptr @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers21bpf_inode_storage_get(ptr noundef %map, ptr noundef %inode, ptr noundef %value, i64 noundef %flags) unnamed_addr #0 !guid !150 {
start:
  %_0 = tail call noundef ptr inttoptr (i64 145 to ptr)(ptr noundef %map, ptr noundef %inode, ptr noundef %value, i64 noundef %flags) #1
  ret ptr %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_ktime_get_boot_ns
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers21bpf_ktime_get_boot_ns() unnamed_addr #0 !guid !151 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 125 to ptr)() #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_msg_redirect_hash
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers21bpf_msg_redirect_hash(ptr noundef %msg, ptr noundef %map, ptr noundef %key, i64 noundef %flags) unnamed_addr #0 !guid !152 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 71 to ptr)(ptr noundef %msg, ptr noundef %map, ptr noundef %key, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_perf_event_output
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers21bpf_perf_event_output(ptr noundef %ctx, ptr noundef %map, i64 noundef %flags, ptr noundef %data, i64 noundef %size) unnamed_addr #0 !guid !153 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 25 to ptr)(ptr noundef %ctx, ptr noundef %map, i64 noundef %flags, ptr noundef %data, i64 noundef %size) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_probe_read_kernel
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers21bpf_probe_read_kernel(ptr noundef %dst, i32 noundef %size, ptr noundef %unsafe_ptr) unnamed_addr #0 !guid !154 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 113 to ptr)(ptr noundef %dst, i32 noundef %size, ptr noundef %unsafe_ptr) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_sk_storage_delete
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers21bpf_sk_storage_delete(ptr noundef %map, ptr noundef %sk) unnamed_addr #0 !guid !155 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 108 to ptr)(ptr noundef %map, ptr noundef %sk) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_skc_to_mptcp_sock
; Function Attrs: nounwind
define noundef ptr @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers21bpf_skc_to_mptcp_sock(ptr noundef %sk) unnamed_addr #0 !guid !156 {
start:
  %_0 = tail call noundef ptr inttoptr (i64 196 to ptr)(ptr noundef %sk) #1
  ret ptr %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_tcp_gen_syncookie
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers21bpf_tcp_gen_syncookie(ptr noundef %sk, ptr noundef %iph, i32 noundef %iph_len, ptr noundef %th, i32 noundef %th_len) unnamed_addr #0 !guid !157 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 110 to ptr)(ptr noundef %sk, ptr noundef %iph, i32 noundef %iph_len, ptr noundef %th, i32 noundef %th_len) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_get_cgroup_classid
; Function Attrs: nounwind
define noundef i32 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers22bpf_get_cgroup_classid(ptr noundef %skb) unnamed_addr #0 !guid !158 {
start:
  %_0 = tail call noundef i32 inttoptr (i64 17 to ptr)(ptr noundef %skb) #1
  ret i32 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_send_signal_thread
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers22bpf_send_signal_thread(i32 noundef %sig) unnamed_addr #0 !guid !159 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 117 to ptr)(i32 noundef %sig) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_skb_cgroup_classid
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers22bpf_skb_cgroup_classid(ptr noundef %skb) unnamed_addr #0 !guid !160 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 151 to ptr)(ptr noundef %skb) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_skb_get_tunnel_key
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers22bpf_skb_get_tunnel_key(ptr noundef %skb, ptr noundef %key, i32 noundef %size, i64 noundef %flags) unnamed_addr #0 !guid !161 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 20 to ptr)(ptr noundef %skb, ptr noundef %key, i32 noundef %size, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_skb_get_tunnel_opt
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers22bpf_skb_get_tunnel_opt(ptr noundef %skb, ptr noundef %opt, i32 noundef %size) unnamed_addr #0 !guid !162 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 29 to ptr)(ptr noundef %skb, ptr noundef %opt, i32 noundef %size) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_skb_get_xfrm_state
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers22bpf_skb_get_xfrm_state(ptr noundef %skb, i32 noundef %index, ptr noundef %xfrm_state, i32 noundef %size, i64 noundef %flags) unnamed_addr #0 !guid !163 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 66 to ptr)(ptr noundef %skb, i32 noundef %index, ptr noundef %xfrm_state, i32 noundef %size, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_skb_set_tunnel_key
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers22bpf_skb_set_tunnel_key(ptr noundef %skb, ptr noundef %key, i32 noundef %size, i64 noundef %flags) unnamed_addr #0 !guid !164 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 21 to ptr)(ptr noundef %skb, ptr noundef %key, i32 noundef %size, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_skb_set_tunnel_opt
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers22bpf_skb_set_tunnel_opt(ptr noundef %skb, ptr noundef %opt, i32 noundef %size) unnamed_addr #0 !guid !165 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 30 to ptr)(ptr noundef %skb, ptr noundef %opt, i32 noundef %size) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_timer_set_callback
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers22bpf_timer_set_callback(ptr noundef %timer, ptr noundef %callback_fn) unnamed_addr #0 !guid !166 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 170 to ptr)(ptr noundef %timer, ptr noundef %callback_fn) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_user_ringbuf_drain
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers22bpf_user_ringbuf_drain(ptr noundef %map, ptr noundef %callback_fn, ptr noundef %ctx, i64 noundef %flags) unnamed_addr #0 !guid !167 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 209 to ptr)(ptr noundef %map, ptr noundef %callback_fn, ptr noundef %ctx, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_cgrp_storage_delete
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers23bpf_cgrp_storage_delete(ptr noundef %map, ptr noundef %cgroup) unnamed_addr #0 !guid !168 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 211 to ptr)(ptr noundef %map, ptr noundef %cgroup) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_copy_from_user_task
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers23bpf_copy_from_user_task(ptr noundef %dst, i32 noundef %size, ptr noundef %user_ptr, ptr noundef %tsk, i64 noundef %flags) unnamed_addr #0 !guid !169 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 191 to ptr)(ptr noundef %dst, i32 noundef %size, ptr noundef %user_ptr, ptr noundef %tsk, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_get_branch_snapshot
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers23bpf_get_branch_snapshot(ptr noundef %entries, i32 noundef %size, i64 noundef %flags) unnamed_addr #0 !guid !170 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 176 to ptr)(ptr noundef %entries, i32 noundef %size, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_get_current_uid_gid
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers23bpf_get_current_uid_gid() unnamed_addr #0 !guid !171 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 15 to ptr)() #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_ktime_get_coarse_ns
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers23bpf_ktime_get_coarse_ns() unnamed_addr #0 !guid !172 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 160 to ptr)() #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_lwt_seg6_adjust_srh
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers23bpf_lwt_seg6_adjust_srh(ptr noundef %skb, i32 noundef %offset, i32 noundef %delta) unnamed_addr #0 !guid !173 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 75 to ptr)(ptr noundef %skb, i32 noundef %offset, i32 noundef %delta) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_probe_read_user_str
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers23bpf_probe_read_user_str(ptr noundef %dst, i32 noundef %size, ptr noundef %unsafe_ptr) unnamed_addr #0 !guid !174 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 114 to ptr)(ptr noundef %dst, i32 noundef %size, ptr noundef %unsafe_ptr) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_read_branch_records
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers23bpf_read_branch_records(ptr noundef %ctx, ptr noundef %buf, i32 noundef %size, i64 noundef %flags) unnamed_addr #0 !guid !175 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 119 to ptr)(ptr noundef %ctx, ptr noundef %buf, i32 noundef %size, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_sk_select_reuseport
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers23bpf_sk_select_reuseport(ptr noundef %reuse, ptr noundef %map, ptr noundef %key, i64 noundef %flags) unnamed_addr #0 !guid !176 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 82 to ptr)(ptr noundef %reuse, ptr noundef %map, ptr noundef %key, i64 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_task_storage_delete
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers23bpf_task_storage_delete(ptr noundef %map, ptr noundef %task) unnamed_addr #0 !guid !177 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 157 to ptr)(ptr noundef %map, ptr noundef %task) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_tcp_check_syncookie
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers23bpf_tcp_check_syncookie(ptr noundef %sk, ptr noundef %iph, i32 noundef %iph_len, ptr noundef %th, i32 noundef %th_len) unnamed_addr #0 !guid !178 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 100 to ptr)(ptr noundef %sk, ptr noundef %iph, i32 noundef %iph_len, ptr noundef %th, i32 noundef %th_len) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_get_current_pid_tgid
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers24bpf_get_current_pid_tgid() unnamed_addr #0 !guid !179 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 14 to ptr)() #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_get_current_task_btf
; Function Attrs: nounwind
define noundef ptr @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers24bpf_get_current_task_btf() unnamed_addr #0 !guid !180 {
start:
  %_0 = tail call noundef ptr inttoptr (i64 158 to ptr)() #1
  ret ptr %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_get_smp_processor_id
; Function Attrs: nounwind
define noundef i32 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers24bpf_get_smp_processor_id() unnamed_addr #0 !guid !181 {
start:
  %_0 = tail call noundef i32 inttoptr (i64 8 to ptr)() #1
  ret i32 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_inode_storage_delete
; Function Attrs: nounwind
define noundef i32 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers24bpf_inode_storage_delete(ptr noundef %map, ptr noundef %inode) unnamed_addr #0 !guid !182 {
start:
  %_0 = tail call noundef i32 inttoptr (i64 146 to ptr)(ptr noundef %map, ptr noundef %inode) #1
  ret i32 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_kallsyms_lookup_name
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers24bpf_kallsyms_lookup_name(ptr noundef %name, i32 noundef %name_sz, i32 noundef %flags, ptr noundef %res) unnamed_addr #0 !guid !183 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 179 to ptr)(ptr noundef %name, i32 noundef %name_sz, i32 noundef %flags, ptr noundef %res) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_lwt_seg6_store_bytes
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers24bpf_lwt_seg6_store_bytes(ptr noundef %skb, i32 noundef %offset, ptr noundef %from, i32 noundef %len) unnamed_addr #0 !guid !184 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 74 to ptr)(ptr noundef %skb, i32 noundef %offset, ptr noundef %from, i32 noundef %len) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_perf_prog_read_value
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers24bpf_perf_prog_read_value(ptr noundef %ctx, ptr noundef %buf, i32 noundef %buf_size) unnamed_addr #0 !guid !185 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 56 to ptr)(ptr noundef %ctx, ptr noundef %buf, i32 noundef %buf_size) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_sysctl_get_new_value
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers24bpf_sysctl_get_new_value(ptr noundef %ctx, ptr noundef %buf, i64 noundef %buf_len) unnamed_addr #0 !guid !186 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 103 to ptr)(ptr noundef %ctx, ptr noundef %buf, i64 noundef %buf_len) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_sysctl_set_new_value
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers24bpf_sysctl_set_new_value(ptr noundef %ctx, ptr noundef %buf, i64 noundef %buf_len) unnamed_addr #0 !guid !187 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 104 to ptr)(ptr noundef %ctx, ptr noundef %buf, i64 noundef %buf_len) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_btf_find_by_name_kind
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers25bpf_btf_find_by_name_kind(ptr noundef %name, i32 noundef %name_sz, i32 noundef %kind, i32 noundef %flags) unnamed_addr #0 !guid !188 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 167 to ptr)(ptr noundef %name, i32 noundef %name_sz, i32 noundef %kind, i32 noundef %flags) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_get_current_cgroup_id
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers25bpf_get_current_cgroup_id() unnamed_addr #0 !guid !189 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 80 to ptr)() #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_perf_event_read_value
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers25bpf_perf_event_read_value(ptr noundef %map, i64 noundef %flags, ptr noundef %buf, i32 noundef %buf_size) unnamed_addr #0 !guid !190 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 55 to ptr)(ptr noundef %map, i64 noundef %flags, ptr noundef %buf, i32 noundef %buf_size) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_probe_read_kernel_str
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers25bpf_probe_read_kernel_str(ptr noundef %dst, i32 noundef %size, ptr noundef %unsafe_ptr) unnamed_addr #0 !guid !191 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 115 to ptr)(ptr noundef %dst, i32 noundef %size, ptr noundef %unsafe_ptr) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_ringbuf_submit_dynptr
; Function Attrs: nounwind
define void @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers25bpf_ringbuf_submit_dynptr(ptr noundef %ptr, i64 noundef %flags) unnamed_addr #0 !guid !192 {
start:
  tail call void inttoptr (i64 199 to ptr)(ptr noundef %ptr, i64 noundef %flags) #1
  ret void
}

; aya_ebpf_bindings::x86_64::helpers::bpf_sk_ancestor_cgroup_id
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers25bpf_sk_ancestor_cgroup_id(ptr noundef %sk, i32 noundef %ancestor_level) unnamed_addr #0 !guid !193 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 129 to ptr)(ptr noundef %sk, i32 noundef %ancestor_level) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_sock_ops_cb_flags_set
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers25bpf_sock_ops_cb_flags_set(ptr noundef %bpf_sock, i32 noundef %argval) unnamed_addr #0 !guid !194 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 59 to ptr)(ptr noundef %bpf_sock, i32 noundef %argval) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_map_lookup_percpu_elem
; Function Attrs: nounwind
define noundef ptr @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers26bpf_map_lookup_percpu_elem(ptr noundef %map, ptr noundef %key, i32 noundef %cpu) unnamed_addr #0 !guid !195 {
start:
  %_0 = tail call noundef ptr inttoptr (i64 195 to ptr)(ptr noundef %map, ptr noundef %key, i32 noundef %cpu) #1
  ret ptr %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_ringbuf_discard_dynptr
; Function Attrs: nounwind
define void @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers26bpf_ringbuf_discard_dynptr(ptr noundef %ptr, i64 noundef %flags) unnamed_addr #0 !guid !196 {
start:
  tail call void inttoptr (i64 200 to ptr)(ptr noundef %ptr, i64 noundef %flags) #1
  ret void
}

; aya_ebpf_bindings::x86_64::helpers::bpf_ringbuf_reserve_dynptr
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers26bpf_ringbuf_reserve_dynptr(ptr noundef %ringbuf, i32 noundef %size, i64 noundef %flags, ptr noundef %ptr) unnamed_addr #0 !guid !197 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 198 to ptr)(ptr noundef %ringbuf, i32 noundef %size, i64 noundef %flags, ptr noundef %ptr) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_skb_ancestor_cgroup_id
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers26bpf_skb_ancestor_cgroup_id(ptr noundef %skb, i32 noundef %ancestor_level) unnamed_addr #0 !guid !198 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 83 to ptr)(ptr noundef %skb, i32 noundef %ancestor_level) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_get_ns_current_pid_tgid
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers27bpf_get_ns_current_pid_tgid(i64 noundef %dev, i64 noundef %ino, ptr noundef %nsdata, i32 noundef %size) unnamed_addr #0 !guid !199 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 120 to ptr)(i64 noundef %dev, i64 noundef %ino, ptr noundef %nsdata, i32 noundef %size) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_skb_load_bytes_relative
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers27bpf_skb_load_bytes_relative(ptr noundef %skb, i32 noundef %offset, ptr noundef %to, i32 noundef %len, i32 noundef %start_header) unnamed_addr #0 !guid !200 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 68 to ptr)(ptr noundef %skb, i32 noundef %offset, ptr noundef %to, i32 noundef %len, i32 noundef %start_header) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_skc_to_tcp_request_sock
; Function Attrs: nounwind
define noundef ptr @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers27bpf_skc_to_tcp_request_sock(ptr noundef %sk) unnamed_addr #0 !guid !201 {
start:
  %_0 = tail call noundef ptr inttoptr (i64 139 to ptr)(ptr noundef %sk) #1
  ret ptr %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_skc_to_tcp_timewait_sock
; Function Attrs: nounwind
define noundef ptr @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers28bpf_skc_to_tcp_timewait_sock(ptr noundef %sk) unnamed_addr #0 !guid !202 {
start:
  %_0 = tail call noundef ptr inttoptr (i64 138 to ptr)(ptr noundef %sk) #1
  ret ptr %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_sysctl_get_current_value
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers28bpf_sysctl_get_current_value(ptr noundef %ctx, ptr noundef %buf, i64 noundef %buf_len) unnamed_addr #0 !guid !203 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 102 to ptr)(ptr noundef %ctx, ptr noundef %buf, i64 noundef %buf_len) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_current_task_under_cgroup
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers29bpf_current_task_under_cgroup(ptr noundef %map, i32 noundef %index) unnamed_addr #0 !guid !204 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 37 to ptr)(ptr noundef %map, i32 noundef %index) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_tcp_raw_gen_syncookie_ipv4
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers30bpf_tcp_raw_gen_syncookie_ipv4(ptr noundef %iph, ptr noundef %th, i32 noundef %th_len) unnamed_addr #0 !guid !205 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 204 to ptr)(ptr noundef %iph, ptr noundef %th, i32 noundef %th_len) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_tcp_raw_gen_syncookie_ipv6
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers30bpf_tcp_raw_gen_syncookie_ipv6(ptr noundef %iph, ptr noundef %th, i32 noundef %th_len) unnamed_addr #0 !guid !206 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 205 to ptr)(ptr noundef %iph, ptr noundef %th, i32 noundef %th_len) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_tcp_raw_check_syncookie_ipv4
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers32bpf_tcp_raw_check_syncookie_ipv4(ptr noundef %iph, ptr noundef %th) unnamed_addr #0 !guid !207 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 206 to ptr)(ptr noundef %iph, ptr noundef %th) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_tcp_raw_check_syncookie_ipv6
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers32bpf_tcp_raw_check_syncookie_ipv6(ptr noundef %iph, ptr noundef %th) unnamed_addr #0 !guid !208 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 207 to ptr)(ptr noundef %iph, ptr noundef %th) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_get_current_ancestor_cgroup_id
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers34bpf_get_current_ancestor_cgroup_id(i32 noundef %ancestor_level) unnamed_addr #0 !guid !209 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 123 to ptr)(i32 noundef %ancestor_level) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_bind
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers8bpf_bind(ptr noundef %ctx, ptr noundef %addr, i32 noundef %addr_len) unnamed_addr #0 !guid !210 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 64 to ptr)(ptr noundef %ctx, ptr noundef %addr, i32 noundef %addr_len) #1
  ret i64 %_0
}

; aya_ebpf_bindings::x86_64::helpers::bpf_loop
; Function Attrs: nounwind
define noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers8bpf_loop(i32 noundef %nr_loops, ptr noundef %callback_fn, ptr noundef %callback_ctx, i64 noundef %flags) unnamed_addr #0 !guid !211 {
start:
  %_0 = tail call noundef i64 inttoptr (i64 181 to ptr)(i32 noundef %nr_loops, ptr noundef %callback_fn, ptr noundef %callback_ctx, i64 noundef %flags) #1
  ret i64 %_0
}

attributes #0 = { nounwind "target-cpu"="generic" }
attributes #1 = { nounwind }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 8, !"PIC Level", i32 2}
!1 = !{!"rustc version 1.100.0-nightly (a69a63265 2026-09-03)"}
!2 = !{i64 -7362218801502298244}
!3 = !{i64 -5154961692366881615}
!4 = !{i64 4817266516943236594}
!5 = !{i64 -6248243105228976624}
!6 = !{i64 -6631699061948919521}
!7 = !{i64 1218554945501202125}
!8 = !{i64 5607454766950936271}
!9 = !{i64 1197835750821005567}
!10 = !{i64 6401432065107058135}
!11 = !{i64 -4060424941148364644}
!12 = !{i64 -2742464334717765906}
!13 = !{i64 -4614062553995450636}
!14 = !{i64 -6684309573530412524}
!15 = !{i64 4542375786991808778}
!16 = !{i64 -4870484922001340058}
!17 = !{i64 -8194652630207982397}
!18 = !{i64 1742187055840185377}
!19 = !{i64 -3082968754104901436}
!20 = !{i64 188526717444587292}
!21 = !{i64 6360843282066463400}
!22 = !{i64 3784184965429909875}
!23 = !{i64 -2918735543446969446}
!24 = !{i64 -4898200041121952941}
!25 = !{i64 7141121616550787393}
!26 = !{i64 3258910241706283944}
!27 = !{i64 -9125652699836916532}
!28 = !{i64 4475321365565412953}
!29 = !{i64 342804388739311485}
!30 = !{i64 -6203879397753992942}
!31 = !{i64 8299953189824491091}
!32 = !{i64 8869305823416756929}
!33 = !{i64 -7165588704940186805}
!34 = !{i64 -359344056818962410}
!35 = !{i64 638370303981826572}
!36 = !{i64 744742520989604412}
!37 = !{i64 324648006664850108}
!38 = !{i64 7996842394583667557}
!39 = !{i64 -3731726152266486271}
!40 = !{i64 -7509696884894606705}
!41 = !{i64 1282610318208229685}
!42 = !{i64 8159486031660006232}
!43 = !{i64 -4040373037048723940}
!44 = !{i64 1672226403431572835}
!45 = !{i64 1657794508640863891}
!46 = !{i64 -910103225372072534}
!47 = !{i64 -2772301047859819829}
!48 = !{i64 -6392173485998532986}
!49 = !{i64 -5938227957972811133}
!50 = !{i64 4221367084626175159}
!51 = !{i64 7760324377433501586}
!52 = !{i64 -6182442878959342306}
!53 = !{i64 3230113940472078192}
!54 = !{i64 -3600483287690867528}
!55 = !{i64 6177631852300654623}
!56 = !{i64 2999614451803900452}
!57 = !{i64 3463902766210379131}
!58 = !{i64 -5410231043194972827}
!59 = !{i64 -597509960209824644}
!60 = !{i64 62636118264829060}
!61 = !{i64 -6273155405514398627}
!62 = !{i64 -1141095878161215174}
!63 = !{i64 5156574726660813925}
!64 = !{i64 9143420186438214792}
!65 = !{i64 -1332345640007207779}
!66 = !{i64 6320106268919596843}
!67 = !{i64 1132591302857708254}
!68 = !{i64 487740723726065985}
!69 = !{i64 -7379820422076596164}
!70 = !{i64 -106798805228129747}
!71 = !{i64 7267973104668440116}
!72 = !{i64 -8498390555719411093}
!73 = !{i64 -3340149261686497400}
!74 = !{i64 7209614945330374159}
!75 = !{i64 -9096436835136210862}
!76 = !{i64 -3383836427228593784}
!77 = !{i64 -6710466837964841795}
!78 = !{i64 -4067029016687706915}
!79 = !{i64 7116486279556015177}
!80 = !{i64 -3791136435921212671}
!81 = !{i64 -5393231599628617218}
!82 = !{i64 -7739603217906899639}
!83 = !{i64 1265811698641986431}
!84 = !{i64 -8542342859248011273}
!85 = !{i64 4971973295751751687}
!86 = !{i64 7076188714451544943}
!87 = !{i64 -8175620158296171846}
!88 = !{i64 -4367588848320832511}
!89 = !{i64 963644031274377067}
!90 = !{i64 -5724265792684178067}
!91 = !{i64 -8632996970329421659}
!92 = !{i64 6617600438588812142}
!93 = !{i64 -7957729341136393834}
!94 = !{i64 -46938771106608659}
!95 = !{i64 -3961970765477282493}
!96 = !{i64 -7840073994273760157}
!97 = !{i64 -3096861243720532555}
!98 = !{i64 -8532960153060941758}
!99 = !{i64 6410453821629880443}
!100 = !{i64 7857187487740701573}
!101 = !{i64 -4917603920356695837}
!102 = !{i64 -3848018567400361404}
!103 = !{i64 9003869925365971936}
!104 = !{i64 -7777106569660646656}
!105 = !{i64 4157874396439952029}
!106 = !{i64 -3946813149444011103}
!107 = !{i64 2997415066886228352}
!108 = !{i64 -1583811667172788858}
!109 = !{i64 3178052503371312757}
!110 = !{i64 -8053808014501657833}
!111 = !{i64 7593987700692771039}
!112 = !{i64 -2674909822693730820}
!113 = !{i64 8885898219572591073}
!114 = !{i64 8084757395069485805}
!115 = !{i64 8692384191948207826}
!116 = !{i64 3025164424099303204}
!117 = !{i64 -3710625936699998672}
!118 = !{i64 -558613138306422740}
!119 = !{i64 2015378165452652554}
!120 = !{i64 8100922753333299547}
!121 = !{i64 2183947976228826139}
!122 = !{i64 117115393562694254}
!123 = !{i64 -5476443966753389653}
!124 = !{i64 5545548880706122527}
!125 = !{i64 -1165605249945709124}
!126 = !{i64 -3808351325937043910}
!127 = !{i64 3088580899791203753}
!128 = !{i64 -3995047430381151308}
!129 = !{i64 -6249905397378549457}
!130 = !{i64 -7684803064608228725}
!131 = !{i64 6655720746769934320}
!132 = !{i64 -6655625213142836850}
!133 = !{i64 82657149406604197}
!134 = !{i64 3018852538832527269}
!135 = !{i64 -8314073606029323795}
!136 = !{i64 -5726706538765746871}
!137 = !{i64 3325594842609588908}
!138 = !{i64 -3305789890327842626}
!139 = !{i64 -1776266197701724119}
!140 = !{i64 5423145634954580616}
!141 = !{i64 -1524573984580623586}
!142 = !{i64 -5211238132307566491}
!143 = !{i64 -9175547165099611278}
!144 = !{i64 2725480988023517828}
!145 = !{i64 8304946297297965599}
!146 = !{i64 1593955548878006564}
!147 = !{i64 2388493461710816054}
!148 = !{i64 3267908631484817014}
!149 = !{i64 -4541617126848682156}
!150 = !{i64 2067759510888012209}
!151 = !{i64 6066253293752531087}
!152 = !{i64 3901857767611105864}
!153 = !{i64 6497791581441099332}
!154 = !{i64 3594980241810046719}
!155 = !{i64 128175685319027891}
!156 = !{i64 -5798832212855596699}
!157 = !{i64 2062632067073553114}
!158 = !{i64 -6622145613175103540}
!159 = !{i64 6216777331284077157}
!160 = !{i64 5000535025781356932}
!161 = !{i64 7018953969319458788}
!162 = !{i64 -4545328665789947708}
!163 = !{i64 8132543696661211650}
!164 = !{i64 5359696307791904508}
!165 = !{i64 -532387431032008278}
!166 = !{i64 -3171213912427493725}
!167 = !{i64 8898421389311266215}
!168 = !{i64 -6991911499084470414}
!169 = !{i64 6474832640138080095}
!170 = !{i64 -8350279572118505603}
!171 = !{i64 -3364879286345144538}
!172 = !{i64 -3590986603962289163}
!173 = !{i64 -1506717142638110952}
!174 = !{i64 -3505655506544377914}
!175 = !{i64 -5376293509744296787}
!176 = !{i64 6054351429953626215}
!177 = !{i64 -7838438328851024852}
!178 = !{i64 -1379954784358030858}
!179 = !{i64 -6994131663868742833}
!180 = !{i64 -4925345226548459502}
!181 = !{i64 8236453164835629771}
!182 = !{i64 -1742755542215376709}
!183 = !{i64 7958547312499925372}
!184 = !{i64 7116490979601575136}
!185 = !{i64 -1876118957127467649}
!186 = !{i64 5269799276279388278}
!187 = !{i64 -2298570952920718678}
!188 = !{i64 -3419255193289397926}
!189 = !{i64 -565709967776529534}
!190 = !{i64 2587941776066902079}
!191 = !{i64 1869367797074838532}
!192 = !{i64 -6903150321083717703}
!193 = !{i64 4470479203253252664}
!194 = !{i64 3754213488168293765}
!195 = !{i64 -2172948140369471508}
!196 = !{i64 -1322070761644798812}
!197 = !{i64 -6265163091907408276}
!198 = !{i64 -1851064443159520796}
!199 = !{i64 -2658535975831964432}
!200 = !{i64 1991727404315560041}
!201 = !{i64 4250312819887216420}
!202 = !{i64 -5621821902216858448}
!203 = !{i64 3415432135824688416}
!204 = !{i64 5508632987120844110}
!205 = !{i64 6499558887732579429}
!206 = !{i64 1162723516403522126}
!207 = !{i64 -7891910501849267650}
!208 = !{i64 2625291904876317539}
!209 = !{i64 -2375050417866291932}
!210 = !{i64 8663072777040920287}
!211 = !{i64 -5828349364572542318}
