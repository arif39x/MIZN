; ModuleID = 'aya_ebpf.8acc9bfd663393e8-cgu.0'
source_filename = "aya_ebpf.8acc9bfd663393e8-cgu.0"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

; <aya_ebpf::programs::sk_msg::SkMsgContext>::pop_data
; Function Attrs: nounwind
define [2 x i64] @_RNvMNtNtCsbUP9Za6eZmK_8aya_ebpf8programs6sk_msgNtB2_12SkMsgContext8pop_data(ptr noalias nofree noundef readonly align 8 captures(none) dereferenceable(8) %self, i32 noundef %start1, i32 noundef %len, i64 noundef %flags) unnamed_addr #0 !guid !2 {
start:
  %_6 = load ptr, ptr %self, align 8, !noundef !3
; call aya_ebpf_bindings::x86_64::helpers::bpf_msg_pop_data
  %ret = tail call noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers16bpf_msg_pop_data(ptr noundef %_6, i32 noundef %start1, i32 noundef %len, i64 noundef %flags) #3
  %0 = icmp ne i64 %ret, 0
  %. = zext i1 %0 to i64
  %.fca.0.insert = insertvalue [2 x i64] poison, i64 %., 0
  %.fca.1.insert = insertvalue [2 x i64] %.fca.0.insert, i64 %ret, 1
  ret [2 x i64] %.fca.1.insert
}

; <aya_ebpf::programs::sk_msg::SkMsgContext>::push_data
; Function Attrs: nounwind
define [2 x i64] @_RNvMNtNtCsbUP9Za6eZmK_8aya_ebpf8programs6sk_msgNtB2_12SkMsgContext9push_data(ptr noalias nofree noundef readonly align 8 captures(none) dereferenceable(8) %self, i32 noundef %start1, i32 noundef %len, i64 noundef %flags) unnamed_addr #0 !guid !4 {
start:
  %_6 = load ptr, ptr %self, align 8, !noundef !3
; call aya_ebpf_bindings::x86_64::helpers::bpf_msg_push_data
  %ret = tail call noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers17bpf_msg_push_data(ptr noundef %_6, i32 noundef %start1, i32 noundef %len, i64 noundef %flags) #3
  %0 = icmp ne i64 %ret, 0
  %. = zext i1 %0 to i64
  %.fca.0.insert = insertvalue [2 x i64] poison, i64 %., 0
  %.fca.1.insert = insertvalue [2 x i64] %.fca.0.insert, i64 %ret, 1
  ret [2 x i64] %.fca.1.insert
}

; <aya_ebpf::programs::sock_ops::SockOpsContext>::set_cb_flags
; Function Attrs: nounwind
define [2 x i64] @_RNvMNtNtCsbUP9Za6eZmK_8aya_ebpf8programs8sock_opsNtB2_14SockOpsContext12set_cb_flags(ptr noalias nofree noundef readonly align 8 captures(none) dereferenceable(8) %self, i32 noundef %flags) unnamed_addr #0 !guid !5 {
start:
  %_4 = load ptr, ptr %self, align 8, !noundef !3
; call aya_ebpf_bindings::x86_64::helpers::bpf_sock_ops_cb_flags_set
  %ret = tail call noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers25bpf_sock_ops_cb_flags_set(ptr noundef %_4, i32 noundef %flags) #3
  %0 = icmp ne i64 %ret, 0
  %. = zext i1 %0 to i64
  %.fca.0.insert = insertvalue [2 x i64] poison, i64 %., 0
  %.fca.1.insert = insertvalue [2 x i64] %.fca.0.insert, i64 %ret, 1
  ret [2 x i64] %.fca.1.insert
}

; <aya_ebpf::maps::ring_buf::RingBuf>::query
; Function Attrs: nounwind
define noundef i64 @_RNvMs2_NtNtCsbUP9Za6eZmK_8aya_ebpf4maps8ring_bufNtB5_7RingBuf5query(ptr noundef nonnull align 4 %self, i64 noundef %flags) unnamed_addr #0 !guid !6 {
start:
; call aya_ebpf_bindings::x86_64::helpers::bpf_ringbuf_query
  %_0 = tail call noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers17bpf_ringbuf_query(ptr noundef nonnull %self, i64 noundef %flags) #3
  ret i64 %_0
}

; <aya_ebpf::maps::sock_map::SockMap>::redirect_msg
; Function Attrs: nounwind
define noundef i64 @_RNvMs_NtNtCsbUP9Za6eZmK_8aya_ebpf4maps8sock_mapNtB4_7SockMap12redirect_msg(ptr noundef nonnull align 4 %self, ptr noalias nofree noundef readonly align 8 captures(none) dereferenceable(8) %ctx, i32 noundef %index, i64 noundef %flags) unnamed_addr #0 !guid !7 {
start:
  %_6 = load ptr, ptr %ctx, align 8, !noundef !3
; call aya_ebpf_bindings::x86_64::helpers::bpf_msg_redirect_map
  %_0 = tail call noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers20bpf_msg_redirect_map(ptr noundef %_6, ptr noundef nonnull %self, i32 noundef %index, i64 noundef %flags) #3
  ret i64 %_0
}

; <aya_ebpf::maps::sock_map::SockMap>::redirect_skb
; Function Attrs: nounwind
define noundef i64 @_RNvMs_NtNtCsbUP9Za6eZmK_8aya_ebpf4maps8sock_mapNtB4_7SockMap12redirect_skb(ptr noundef nonnull align 4 %self, ptr noalias nofree noundef readonly align 8 captures(none) dereferenceable(8) %ctx, i32 noundef %index, i64 noundef %flags) unnamed_addr #0 !guid !8 {
start:
  %_6 = load ptr, ptr %ctx, align 8, !noundef !3
; call aya_ebpf_bindings::x86_64::helpers::bpf_sk_redirect_map
  %_0 = tail call noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_sk_redirect_map(ptr noundef %_6, ptr noundef nonnull %self, i32 noundef %index, i64 noundef %flags) #3
  ret i64 %_0
}

; <aya_ebpf::maps::sock_map::SockMap>::redirect_sk_lookup
; Function Attrs: nounwind
define range(i64 4294967296, 4294967298) i64 @_RNvMs_NtNtCsbUP9Za6eZmK_8aya_ebpf4maps8sock_mapNtB4_7SockMap18redirect_sk_lookup(ptr noalias nofree noundef align 4 dereferenceable(28) %self, ptr noalias nofree noundef readonly align 8 captures(none) dereferenceable(8) %ctx, i32 noundef %0, i64 noundef %flags) unnamed_addr #0 !guid !9 {
start:
  %index = alloca [4 x i8], align 4
  store i32 %0, ptr %index, align 4
; call aya_ebpf_bindings::x86_64::helpers::bpf_map_lookup_elem
  %sk = call noundef ptr @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_map_lookup_elem(ptr noundef nonnull %self, ptr noundef nonnull %index) #3
  %_10 = icmp eq ptr %sk, null
  br i1 %_10, label %bb6, label %bb3

bb3:                                              ; preds = %start
  %_15 = load ptr, ptr %ctx, align 8, !noundef !3
; call aya_ebpf_bindings::x86_64::helpers::bpf_sk_assign
  %ret = call noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers13bpf_sk_assign(ptr noundef %_15, ptr noundef nonnull %sk, i64 noundef %flags) #3
; call aya_ebpf_bindings::x86_64::helpers::bpf_sk_release
  %_13 = call noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers14bpf_sk_release(ptr noundef nonnull %sk) #3
  %1 = icmp eq i64 %ret, 0
  %. = select i1 %1, i64 4294967296, i64 4294967297
  br label %bb6

bb6:                                              ; preds = %start, %bb3
  %_0.sroa.0.0 = phi i64 [ %., %bb3 ], [ 4294967297, %start ]
  ret i64 %_0.sroa.0.0
}

; <aya_ebpf::maps::sock_map::SockMap>::update
; Function Attrs: nounwind
define [2 x i64] @_RNvMs_NtNtCsbUP9Za6eZmK_8aya_ebpf4maps8sock_mapNtB4_7SockMap6update(ptr noundef nonnull align 4 %self, i32 noundef %0, ptr noundef %sk_ops, i64 noundef %flags) unnamed_addr #0 !guid !10 {
start:
  %index = alloca [4 x i8], align 4
  store i32 %0, ptr %index, align 4
; call aya_ebpf_bindings::x86_64::helpers::bpf_sock_map_update
  %ret = call noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_sock_map_update(ptr noundef %sk_ops, ptr noundef nonnull %self, ptr noundef nonnull %index, i64 noundef %flags) #3
  %1 = icmp ne i64 %ret, 0
  %. = zext i1 %1 to i64
  %.fca.0.insert = insertvalue [2 x i64] poison, i64 %., 0
  %.fca.1.insert = insertvalue [2 x i64] %.fca.0.insert, i64 %ret, 1
  ret [2 x i64] %.fca.1.insert
}

; Function Attrs: nofree norecurse nosync nounwind memory(argmem: readwrite)
define void @memcpy(ptr nofree noundef writeonly captures(none) %dest, ptr nofree noundef readonly captures(none) %src, i64 noundef %n) unnamed_addr #1 !guid !11 {
start:
  %_72.not = icmp eq i64 %n, 0
  br i1 %_72.not, label %bb3, label %bb2

bb3:                                              ; preds = %bb2, %start
  ret void

bb2:                                              ; preds = %start, %bb2
  %_9.sroa.0.03 = phi i64 [ %0, %bb2 ], [ 0, %start ]
  %0 = add nuw i64 %_9.sroa.0.03, 1
  %_5 = getelementptr inbounds nuw i8, ptr %src, i64 %_9.sroa.0.03
  %_4 = load i8, ptr %_5, align 1, !noundef !3
  %_6 = getelementptr inbounds nuw i8, ptr %dest, i64 %_9.sroa.0.03
  store i8 %_4, ptr %_6, align 1
  %_7 = icmp ult i64 %0, %n
  br i1 %_7, label %bb2, label %bb3
}

; Function Attrs: nofree norecurse nosync nounwind memory(argmem: readwrite)
define void @memmove(ptr noundef %dest, ptr noundef %src, i64 noundef %0) unnamed_addr #1 !guid !12 {
start:
  %_5 = ptrtoint ptr %dest to i64
  %_6 = ptrtoint ptr %src to i64
  %delta = sub i64 %_5, %_6
  %_7.not = icmp ult i64 %delta, %0
  br i1 %_7.not, label %bb8, label %bb4.preheader

bb4.preheader:                                    ; preds = %start
  %_117.not = icmp eq i64 %0, 0
  br i1 %_117.not, label %bb3, label %bb5

bb8:                                              ; preds = %start, %bb8
  %n.sroa.0.09 = phi i64 [ %_19, %bb8 ], [ %0, %start ]
  %_19 = add i64 %n.sroa.0.09, -1
  %_16 = getelementptr inbounds nuw i8, ptr %src, i64 %_19
  %_15 = load i8, ptr %_16, align 1, !noundef !3
  %_17 = getelementptr inbounds nuw i8, ptr %dest, i64 %_19
  store i8 %_15, ptr %_17, align 1
  %_18.not = icmp eq i64 %_19, 0
  br i1 %_18.not, label %bb3, label %bb8

bb3:                                              ; preds = %bb5, %bb8, %bb4.preheader
  ret void

bb5:                                              ; preds = %bb4.preheader, %bb5
  %_13.sroa.0.08 = phi i64 [ %1, %bb5 ], [ 0, %bb4.preheader ]
  %1 = add nuw i64 %_13.sroa.0.08, 1
  %_9 = getelementptr inbounds nuw i8, ptr %src, i64 %_13.sroa.0.08
  %_8 = load i8, ptr %_9, align 1, !noundef !3
  %_10 = getelementptr inbounds nuw i8, ptr %dest, i64 %_13.sroa.0.08
  store i8 %_8, ptr %_10, align 1
  %_11 = icmp ult i64 %1, %0
  br i1 %_11, label %bb5, label %bb3
}

; Function Attrs: nofree norecurse nosync nounwind memory(argmem: write)
define void @memset(ptr nofree noundef writeonly captures(none) %s, i32 noundef %c, i64 noundef %n) unnamed_addr #2 !guid !13 {
start:
  %b = trunc i32 %c to i8
  %_82.not = icmp eq i64 %n, 0
  br i1 %_82.not, label %bb3, label %bb2

bb3:                                              ; preds = %bb2, %start
  ret void

bb2:                                              ; preds = %start, %bb2
  %iter.sroa.0.03 = phi i64 [ %0, %bb2 ], [ 0, %start ]
  %0 = add nuw i64 %iter.sroa.0.03, 1
  %_7 = getelementptr inbounds nuw i8, ptr %s, i64 %iter.sroa.0.03
  store i8 %b, ptr %_7, align 1
  %_8 = icmp ult i64 %0, %n
  br i1 %_8, label %bb2, label %bb3
}

; aya_ebpf_bindings::x86_64::helpers::bpf_msg_pop_data
; Function Attrs: nounwind
declare noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers16bpf_msg_pop_data(ptr noundef, i32 noundef, i32 noundef, i64 noundef) unnamed_addr #0

; aya_ebpf_bindings::x86_64::helpers::bpf_msg_push_data
; Function Attrs: nounwind
declare noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers17bpf_msg_push_data(ptr noundef, i32 noundef, i32 noundef, i64 noundef) unnamed_addr #0

; aya_ebpf_bindings::x86_64::helpers::bpf_sock_ops_cb_flags_set
; Function Attrs: nounwind
declare noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers25bpf_sock_ops_cb_flags_set(ptr noundef, i32 noundef) unnamed_addr #0

; aya_ebpf_bindings::x86_64::helpers::bpf_ringbuf_query
; Function Attrs: nounwind
declare noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers17bpf_ringbuf_query(ptr noundef, i64 noundef) unnamed_addr #0

; aya_ebpf_bindings::x86_64::helpers::bpf_msg_redirect_map
; Function Attrs: nounwind
declare noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers20bpf_msg_redirect_map(ptr noundef, ptr noundef, i32 noundef, i64 noundef) unnamed_addr #0

; aya_ebpf_bindings::x86_64::helpers::bpf_sk_redirect_map
; Function Attrs: nounwind
declare noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_sk_redirect_map(ptr noundef, ptr noundef, i32 noundef, i64 noundef) unnamed_addr #0

; aya_ebpf_bindings::x86_64::helpers::bpf_map_lookup_elem
; Function Attrs: nounwind
declare noundef ptr @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_map_lookup_elem(ptr noundef, ptr noundef) unnamed_addr #0

; aya_ebpf_bindings::x86_64::helpers::bpf_sk_assign
; Function Attrs: nounwind
declare noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers13bpf_sk_assign(ptr noundef, ptr noundef, i64 noundef) unnamed_addr #0

; aya_ebpf_bindings::x86_64::helpers::bpf_sk_release
; Function Attrs: nounwind
declare noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers14bpf_sk_release(ptr noundef) unnamed_addr #0

; aya_ebpf_bindings::x86_64::helpers::bpf_sock_map_update
; Function Attrs: nounwind
declare noundef i64 @_RNvNtNtCsiyLVQjXIThM_17aya_ebpf_bindings6x86_647helpers19bpf_sock_map_update(ptr noundef, ptr noundef, ptr noundef, i64 noundef) unnamed_addr #0

attributes #0 = { nounwind "target-cpu"="generic" }
attributes #1 = { nofree norecurse nosync nounwind memory(argmem: readwrite) "target-cpu"="generic" }
attributes #2 = { nofree norecurse nosync nounwind memory(argmem: write) "target-cpu"="generic" }
attributes #3 = { nounwind }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 8, !"PIC Level", i32 2}
!1 = !{!"rustc version 1.100.0-nightly (a69a63265 2026-09-03)"}
!2 = !{i64 -7729424989990215058}
!3 = !{}
!4 = !{i64 133199897540670023}
!5 = !{i64 -6760297587036121315}
!6 = !{i64 937098393036711198}
!7 = !{i64 2982088052065730359}
!8 = !{i64 -6809296400894323601}
!9 = !{i64 -8403353863955738846}
!10 = !{i64 7115442155810691032}
!11 = !{i64 3893303423671325810}
!12 = !{i64 -306081897096246147}
!13 = !{i64 -2741574704065975695}
