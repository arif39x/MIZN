; ModuleID = 'bytemuck.8219f97bb277d708-cgu.0'
source_filename = "bytemuck.8219f97bb277d708-cgu.0"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

@alloc_0c812808379efded5a4fb82d2790b556 = private unnamed_addr constant [2 x i8] c"\C0\00", align 1, !guid !0
@alloc_7affa7606dfbd432802a02068ccbac8e = private unnamed_addr constant [40 x i8] c"TargetAlignmentGreaterAndInputNotAligned", align 1, !guid !1
@alloc_928d830575500328ad1cb2d08eb96d4c = private unnamed_addr constant [24 x i8] c"OutputSliceWouldHaveSlop", align 1, !guid !2
@alloc_716be54c727d8800daf34f8cc8d7342f = private unnamed_addr constant [12 x i8] c"SizeMismatch", align 1, !guid !3
@alloc_64ccd95505c8ce927aaedda24184ce81 = private unnamed_addr constant [17 x i8] c"AlignmentMismatch", align 1, !guid !4
@vtable.0 = private unnamed_addr constant <{ [24 x i8], ptr }> <{ [24 x i8] c"\00\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00", ptr @_RNvXs1g_NtCslFG8s6jZi6P_4core3fmtRNtCsbawFVcTuigu_8bytemuck12PodCastErrorNtB6_5Debug3fmtBy_ }>, align 8, !guid !5
@alloc_30a29e5961f86fecc80e46d3202bc566 = private unnamed_addr constant [12 x i8] c"PodCastError", align 1, !guid !6
@alloc_f09d42857c8423ff15e7133b5094dc02 = private unnamed_addr constant [17 x i8] c"InvalidBitPattern", align 1, !guid !7

; <bytemuck::PodCastError as core::fmt::Display>::fmt
; Function Attrs: nounwind
define noundef zeroext i1 @_RNvXCsbawFVcTuigu_8bytemuckNtB2_12PodCastErrorNtNtCslFG8s6jZi6P_4core3fmt7Display3fmt(ptr noalias nofree noundef readonly captures(address, read_provenance) dereferenceable(1) %0, ptr noalias nofree noundef readonly align 8 captures(none) dereferenceable(24) %f) unnamed_addr #0 !guid !10 {
start:
  %args = alloca [16 x i8], align 8
  %self = alloca [8 x i8], align 8
  store ptr %0, ptr %self, align 8
  call void @llvm.lifetime.start.p0(ptr nonnull %args)
  store ptr %self, ptr %args, align 8
  %_6.sroa.4.0..sroa_idx = getelementptr inbounds nuw i8, ptr %args, i64 8
  store ptr @_RNvXs1g_NtCslFG8s6jZi6P_4core3fmtRNtCsbawFVcTuigu_8bytemuck12PodCastErrorNtB6_5Debug3fmtBy_, ptr %_6.sroa.4.0..sroa_idx, align 8
  %1 = getelementptr inbounds nuw i8, ptr %f, i64 8
  %f.val1 = load ptr, ptr %1, align 8, !nonnull !11, !noundef !11
  %f.val = load ptr, ptr %f, align 8, !nonnull !11, !noundef !11
; call core::fmt::write
  %2 = call noundef zeroext i1 @_RNvNtCslFG8s6jZi6P_4core3fmt5write(ptr noundef nonnull %f.val, ptr noalias nofree noundef nonnull readonly align 8 captures(address, read_provenance) dereferenceable(48) %f.val1, ptr noundef nonnull @alloc_0c812808379efded5a4fb82d2790b556, ptr noundef nonnull %args) #3
  call void @llvm.lifetime.end.p0(ptr nonnull %args)
  ret i1 %2
}

; <bytemuck::checked::CheckedCastError as core::fmt::Display>::fmt
; Function Attrs: nounwind
define noundef zeroext i1 @_RNvXs1_NtCsbawFVcTuigu_8bytemuck7checkedNtB5_16CheckedCastErrorNtNtCslFG8s6jZi6P_4core3fmt7Display3fmt(ptr noalias nofree noundef readonly captures(address, read_provenance) dereferenceable(1) %0, ptr noalias nofree noundef readonly align 8 captures(none) dereferenceable(24) %f) unnamed_addr #0 !guid !12 {
start:
  %args = alloca [16 x i8], align 8
  %self = alloca [8 x i8], align 8
  store ptr %0, ptr %self, align 8
  call void @llvm.lifetime.start.p0(ptr nonnull %args)
  store ptr %self, ptr %args, align 8
  %_6.sroa.4.0..sroa_idx = getelementptr inbounds nuw i8, ptr %args, i64 8
  store ptr @_RNvXs1g_NtCslFG8s6jZi6P_4core3fmtRNtNtCsbawFVcTuigu_8bytemuck7checked16CheckedCastErrorNtB6_5Debug3fmtBA_, ptr %_6.sroa.4.0..sroa_idx, align 8
  %1 = getelementptr inbounds nuw i8, ptr %f, i64 8
  %f.val1 = load ptr, ptr %1, align 8, !nonnull !11, !noundef !11
  %f.val = load ptr, ptr %f, align 8, !nonnull !11, !noundef !11
; call core::fmt::write
  %2 = call noundef zeroext i1 @_RNvNtCslFG8s6jZi6P_4core3fmt5write(ptr noundef nonnull %f.val, ptr noalias nofree noundef nonnull readonly align 8 captures(address, read_provenance) dereferenceable(48) %f.val1, ptr noundef nonnull @alloc_0c812808379efded5a4fb82d2790b556, ptr noundef nonnull %args) #3
  call void @llvm.lifetime.end.p0(ptr nonnull %args)
  ret i1 %2
}

; <&bytemuck::PodCastError as core::fmt::Debug>::fmt
; Function Attrs: nounwind
define internal noundef zeroext i1 @_RNvXs1g_NtCslFG8s6jZi6P_4core3fmtRNtCsbawFVcTuigu_8bytemuck12PodCastErrorNtB6_5Debug3fmtBy_(ptr noalias nofree noundef readonly align 8 captures(none) dereferenceable(8) %self, ptr noalias nofree noundef align 8 dereferenceable(24) %f) unnamed_addr #0 !guid !13 {
start:
  %_3 = load ptr, ptr %self, align 8, !nonnull !11, !noundef !11
  %_3.val = load i8, ptr %_3, align 1, !range !14, !noundef !11
  switch i8 %_3.val, label %default.unreachable [
    i8 0, label %_RNvXs_CsbawFVcTuigu_8bytemuckNtB4_12PodCastErrorNtNtCslFG8s6jZi6P_4core3fmt5Debug3fmt.exit
    i8 1, label %bb4.i
    i8 2, label %bb3.i
    i8 3, label %bb2.i
  ]

default.unreachable:                              ; preds = %start
  unreachable

bb4.i:                                            ; preds = %start
  br label %_RNvXs_CsbawFVcTuigu_8bytemuckNtB4_12PodCastErrorNtNtCslFG8s6jZi6P_4core3fmt5Debug3fmt.exit

bb3.i:                                            ; preds = %start
  br label %_RNvXs_CsbawFVcTuigu_8bytemuckNtB4_12PodCastErrorNtNtCslFG8s6jZi6P_4core3fmt5Debug3fmt.exit

bb2.i:                                            ; preds = %start
  br label %_RNvXs_CsbawFVcTuigu_8bytemuckNtB4_12PodCastErrorNtNtCslFG8s6jZi6P_4core3fmt5Debug3fmt.exit

_RNvXs_CsbawFVcTuigu_8bytemuckNtB4_12PodCastErrorNtNtCslFG8s6jZi6P_4core3fmt5Debug3fmt.exit: ; preds = %start, %bb4.i, %bb3.i, %bb2.i
  %_3.sroa.7.0.i = phi i64 [ 17, %bb2.i ], [ 24, %bb4.i ], [ 12, %bb3.i ], [ 40, %start ]
  %_3.sroa.0.0.i = phi ptr [ @alloc_64ccd95505c8ce927aaedda24184ce81, %bb2.i ], [ @alloc_928d830575500328ad1cb2d08eb96d4c, %bb4.i ], [ @alloc_716be54c727d8800daf34f8cc8d7342f, %bb3.i ], [ @alloc_7affa7606dfbd432802a02068ccbac8e, %start ]
; call <core::fmt::Formatter>::write_str
  %_0.i = tail call noundef zeroext i1 @_RNvMsa_NtCslFG8s6jZi6P_4core3fmtNtB5_9Formatter9write_str(ptr noalias nofree noundef nonnull align 8 dereferenceable(24) %f, ptr noalias nofree noundef nonnull readonly captures(address, read_provenance) %_3.sroa.0.0.i, i64 noundef %_3.sroa.7.0.i) #3
  ret i1 %_0.i
}

; <&bytemuck::checked::CheckedCastError as core::fmt::Debug>::fmt
; Function Attrs: nounwind
define internal noundef zeroext i1 @_RNvXs1g_NtCslFG8s6jZi6P_4core3fmtRNtNtCsbawFVcTuigu_8bytemuck7checked16CheckedCastErrorNtB6_5Debug3fmtBA_(ptr noalias nofree noundef readonly align 8 captures(none) dereferenceable(8) %self, ptr noalias nofree noundef align 8 dereferenceable(24) %f) unnamed_addr #0 !guid !15 {
start:
  %__self_0.i = alloca [8 x i8], align 8
  %_3 = load ptr, ptr %self, align 8, !nonnull !11, !noundef !11
  tail call void @llvm.experimental.noalias.scope.decl(metadata !16)
  %0 = load i8, ptr %_3, align 1, !range !19, !alias.scope !16, !noalias !20, !noundef !11
  %1 = icmp eq i8 %0, -1
  br i1 %1, label %bb2.i, label %bb3.i

bb2.i:                                            ; preds = %start
; call <core::fmt::Formatter>::write_str
  %2 = tail call noundef zeroext i1 @_RNvMsa_NtCslFG8s6jZi6P_4core3fmtNtB5_9Formatter9write_str(ptr noalias nofree noundef nonnull align 8 dereferenceable(24) %f, ptr noalias nofree noundef nonnull readonly captures(address, read_provenance) @alloc_f09d42857c8423ff15e7133b5094dc02, i64 noundef 17) #3, !noalias !16
  br label %_RNvXsf_NtCsbawFVcTuigu_8bytemuck7checkedNtB5_16CheckedCastErrorNtNtCslFG8s6jZi6P_4core3fmt5Debug3fmt.exit

bb3.i:                                            ; preds = %start
  call void @llvm.lifetime.start.p0(ptr nonnull %__self_0.i), !noalias !22
  store ptr %_3, ptr %__self_0.i, align 8, !noalias !22
; call <core::fmt::Formatter>::debug_tuple_field1_finish
  %3 = call noundef zeroext i1 @_RNvMsa_NtCslFG8s6jZi6P_4core3fmtNtB5_9Formatter25debug_tuple_field1_finish(ptr noalias nofree noundef nonnull align 8 dereferenceable(24) %f, ptr noalias nofree noundef nonnull readonly captures(address, read_provenance) @alloc_30a29e5961f86fecc80e46d3202bc566, i64 noundef 12, ptr noundef nonnull %__self_0.i, ptr noalias nofree noundef readonly align 8 captures(address, read_provenance) dereferenceable(32) @vtable.0) #3
  call void @llvm.lifetime.end.p0(ptr nonnull %__self_0.i), !noalias !22
  br label %_RNvXsf_NtCsbawFVcTuigu_8bytemuck7checkedNtB5_16CheckedCastErrorNtNtCslFG8s6jZi6P_4core3fmt5Debug3fmt.exit

_RNvXsf_NtCsbawFVcTuigu_8bytemuck7checkedNtB5_16CheckedCastErrorNtNtCslFG8s6jZi6P_4core3fmt5Debug3fmt.exit: ; preds = %bb2.i, %bb3.i
  %_0.sroa.0.0.in.i = phi i1 [ %2, %bb2.i ], [ %3, %bb3.i ]
  ret i1 %_0.sroa.0.0.in.i
}

; Function Attrs: mustprogress nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(ptr captures(none)) #1

; Function Attrs: mustprogress nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(ptr captures(none)) #1

; core::fmt::write
; Function Attrs: nounwind
declare noundef zeroext i1 @_RNvNtCslFG8s6jZi6P_4core3fmt5write(ptr noundef nonnull, ptr noalias nofree noundef readonly align 8 captures(address, read_provenance) dereferenceable(48), ptr noundef nonnull, ptr noundef nonnull) unnamed_addr #0

; <core::fmt::Formatter>::write_str
; Function Attrs: nounwind
declare noundef zeroext i1 @_RNvMsa_NtCslFG8s6jZi6P_4core3fmtNtB5_9Formatter9write_str(ptr noalias nofree noundef align 8 dereferenceable(24), ptr noalias nofree noundef nonnull readonly captures(address, read_provenance), i64 noundef) unnamed_addr #0

; <core::fmt::Formatter>::debug_tuple_field1_finish
; Function Attrs: nounwind
declare noundef zeroext i1 @_RNvMsa_NtCslFG8s6jZi6P_4core3fmtNtB5_9Formatter25debug_tuple_field1_finish(ptr noalias nofree noundef align 8 dereferenceable(24), ptr noalias nofree noundef nonnull readonly captures(address, read_provenance), i64 noundef, ptr noundef nonnull, ptr noalias nofree noundef readonly align 8 captures(address, read_provenance) dereferenceable(32)) unnamed_addr #0

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(inaccessiblemem: readwrite)
declare void @llvm.experimental.noalias.scope.decl(metadata) #2

attributes #0 = { nounwind "target-cpu"="generic" }
attributes #1 = { mustprogress nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nocallback nofree nosync nounwind willreturn memory(inaccessiblemem: readwrite) }
attributes #3 = { nounwind }

!llvm.module.flags = !{!8}
!llvm.ident = !{!9}

!0 = !{i64 -2570119706430170451}
!1 = !{i64 8263712451825378220}
!2 = !{i64 75760791538618063}
!3 = !{i64 -5140322789820054381}
!4 = !{i64 7929697772862029604}
!5 = !{i64 -3314631415731046448}
!6 = !{i64 -8646788852790782026}
!7 = !{i64 -2545695198251657517}
!8 = !{i32 8, !"PIC Level", i32 2}
!9 = !{!"rustc version 1.100.0-nightly (a69a63265 2026-09-03)"}
!10 = !{i64 -5090290225067706947}
!11 = !{}
!12 = !{i64 293337476045324139}
!13 = !{i64 4751696513821269649}
!14 = !{i8 0, i8 4}
!15 = !{i64 5198299909165063676}
!16 = !{!17}
!17 = distinct !{!17, !18, !"_RNvXsf_NtCsbawFVcTuigu_8bytemuck7checkedNtB5_16CheckedCastErrorNtNtCslFG8s6jZi6P_4core3fmt5Debug3fmt: %self"}
!18 = distinct !{!18, !"_RNvXsf_NtCsbawFVcTuigu_8bytemuck7checkedNtB5_16CheckedCastErrorNtNtCslFG8s6jZi6P_4core3fmt5Debug3fmt"}
!19 = !{i8 -1, i8 4}
!20 = !{!21}
!21 = distinct !{!21, !18, !"_RNvXsf_NtCsbawFVcTuigu_8bytemuck7checkedNtB5_16CheckedCastErrorNtNtCslFG8s6jZi6P_4core3fmt5Debug3fmt: %f"}
!22 = !{!17, !21}
