; ModuleID = 'mizn_ebpf.d8a82d2267a5035f-cgu.0'
source_filename = "mizn_ebpf.d8a82d2267a5035f-cgu.0"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

@BLOCKLIST = global [28 x i8] c"\01\00\00\00\04\00\00\00\01\00\00\00\00\04\00\00\00\00\00\00\00\00\00\00\00\00\00\00", section "maps", align 4, !guid !0
@BLOCKLIST_V6 = global [28 x i8] c"\01\00\00\00\10\00\00\00\01\00\00\00\00\01\00\00\00\00\00\00\00\00\00\00\00\00\00\00", section "maps", align 4, !guid !1
@FLOW_METRICS = global [28 x i8] c"\01\00\00\00\10\00\00\00X\00\00\00\00(\00\00\00\00\00\00\00\00\00\00\00\00\00\00", section "maps", align 4, !guid !2
@PORT_TO_PID = local_unnamed_addr global [28 x i8] c"\01\00\00\00\04\00\00\00\04\00\00\00\00\00\01\00\00\00\00\00\00\00\00\00\00\00\00\00", section "maps", align 4, !guid !3

; Function Attrs: nounwind
define dso_local noundef range(i32 0, 3) i32 @mizn_ebpf(ptr nofree noundef readonly captures(none) %ctx) unnamed_addr #0 section "xdp" !guid !8 {
start:
  %fresh.i.i644.i = alloca [88 x i8], align 8
  %key.i645.i = alloca [16 x i8], align 4
  %fresh.i.i531.i = alloca [88 x i8], align 8
  %key.i532.i = alloca [16 x i8], align 4
  %fresh.i.i418.i = alloca [88 x i8], align 8
  %key.i419.i = alloca [16 x i8], align 4
  %fresh.i.i314.i = alloca [88 x i8], align 8
  %key.i315.i = alloca [16 x i8], align 4
  %fresh.i.i80.i = alloca [88 x i8], align 8
  %key.i81.i = alloca [16 x i8], align 4
  %fresh.i.i43.i = alloca [88 x i8], align 8
  %key.i44.i = alloca [16 x i8], align 4
  %fresh.i.i6.i = alloca [88 x i8], align 8
  %key.i7.i = alloca [16 x i8], align 4
  %fresh.i.i.i = alloca [88 x i8], align 8
  %key.i.i = alloca [16 x i8], align 4
  %_15.i.i = load i32, ptr %ctx, align 4, !noalias !9, !noundef !12
  %_9.i.i = zext i32 %_15.i.i to i64
  %_8.i.i = inttoptr i64 %_9.i.i to ptr
  %0 = getelementptr inbounds nuw i8, ptr %ctx, i64 4
  %_17.i.i = load i32, ptr %0, align 4, !noalias !9, !noundef !12
  %_11.i.i = zext i32 %_17.i.i to i64
  %_10.i.i = inttoptr i64 %_11.i.i to ptr
  %_14.i.i = getelementptr inbounds nuw i8, ptr %_8.i.i, i64 14
  %_13.i.i = icmp samesign ugt ptr %_14.i.i, %_10.i.i
  br i1 %_13.i.i, label %_RNvNvCsiBg6FOfWNuR_9mizn_ebpf9mizn_ebpf9mizn_ebpf.exit, label %bb7.i.i

bb7.i.i:                                          ; preds = %start
  %1 = getelementptr inbounds nuw i8, ptr %_8.i.i, i64 12
  %_7.i.i = load i16, ptr %1, align 2, !noalias !9, !noundef !12
  %ether_type.i.i = tail call i16 @llvm.bswap.i16(i16 %_7.i.i)
  switch i16 %ether_type.i.i, label %_RNvNvCsiBg6FOfWNuR_9mizn_ebpf9mizn_ebpf9mizn_ebpf.exit [
    i16 2048, label %bb3.i.i
    i16 -31011, label %bb2.i.i
  ]

bb3.i.i:                                          ; preds = %bb7.i.i
  %_43.i.i = getelementptr inbounds nuw i8, ptr %_8.i.i, i64 34
  %_42.i.i = icmp samesign ugt ptr %_43.i.i, %_10.i.i
  br i1 %_42.i.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv410parse_ipv4.exit.i, label %bb11.i.i

bb11.i.i:                                         ; preds = %bb3.i.i
  %_53.i.i = getelementptr inbounds nuw i8, ptr %_8.i.i, i64 26
  %_0.i = tail call noundef ptr inttoptr (i64 1 to ptr)(ptr noundef nonnull @BLOCKLIST, ptr noundef nonnull %_53.i.i) #5, !noalias !13
  %_54.i.i = icmp eq ptr %_0.i, null
  br i1 %_54.i.i, label %bb13.i.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv410parse_ipv4.exit.i

bb13.i.i:                                         ; preds = %bb11.i.i
  %2 = getelementptr inbounds nuw i8, ptr %_8.i.i, i64 23
  %protocol.i.i = load i8, ptr %2, align 1, !noalias !13, !noundef !12
  %_14.i2.i = load i8, ptr %_14.i.i, align 4, !noalias !13, !noundef !12
  %_13.i3.i = shl i8 %_14.i2.i, 2
  %3 = and i8 %_13.i3.i, 60
  %narrow.i.i = add nuw nsw i8 %3, 14
  %xport_off.i.i = zext nneg i8 %narrow.i.i to i64
  %src_ip.i.i = load i32, ptr %_53.i.i, align 4, !noalias !13, !noundef !12
  %4 = getelementptr inbounds nuw i8, ptr %_8.i.i, i64 30
  %dst_ip.i.i = load i32, ptr %4, align 4, !noalias !13, !noundef !12
  %_58.i.i = load i32, ptr %0, align 4, !noalias !13, !noundef !12
  %_20.i.i = zext i32 %_58.i.i to i64
  %_60.i.i = load i32, ptr %ctx, align 4, !noalias !13, !noundef !12
  %_21.i.i = zext i32 %_60.i.i to i64
  %_19.i.i = sub nsw i64 %_20.i.i, %_21.i.i
  switch i8 %protocol.i.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv410parse_ipv4.exit.i [
    i8 6, label %bb5.i.i
    i8 17, label %bb5.i.i
    i8 1, label %bb4.i.i
  ]

bb5.i.i:                                          ; preds = %bb13.i.i, %bb13.i.i
  %5 = icmp eq i8 %protocol.i.i, 6
  %_37.i88.i = inttoptr i64 %_21.i.i to ptr
  %_39.i91.i = inttoptr i64 %_20.i.i to ptr
  %_42.i92.i = getelementptr i8, ptr %_37.i88.i, i64 %xport_off.i.i
  br i1 %5, label %bb1.i274.i, label %bb3.i93.i

bb1.i274.i:                                       ; preds = %bb5.i.i
  %_44.i275.i = getelementptr inbounds nuw i8, ptr %_42.i92.i, i64 20
  %_43.i276.i = icmp samesign ugt ptr %_44.i275.i, %_39.i91.i
  br i1 %_43.i276.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv410parse_ipv4.exit.i, label %bb17.i277.i

bb3.i93.i:                                        ; preds = %bb5.i.i
  %_59.i94.i = getelementptr inbounds nuw i8, ptr %_42.i92.i, i64 8
  %_58.i95.i = icmp samesign ugt ptr %_59.i94.i, %_39.i91.i
  br i1 %_58.i95.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv410parse_ipv4.exit.i, label %bb21.i96.i

bb17.i277.i:                                      ; preds = %bb1.i274.i
  %6 = getelementptr inbounds nuw i8, ptr %_42.i92.i, i64 12
  %_12.i278.i = load i8, ptr %6, align 4, !noalias !16, !noundef !12
  %7 = lshr i8 %_12.i278.i, 2
  %8 = and i8 %7, 60
  %_14.i280.i = load i16, ptr %_42.i92.i, align 4, !noalias !16, !noundef !12
  %9 = tail call i16 @llvm.bswap.i16(i16 %_14.i280.i)
  %10 = getelementptr inbounds nuw i8, ptr %_42.i92.i, i64 2
  %_16.i281.i = load i16, ptr %10, align 2, !noalias !16, !noundef !12
  %11 = tail call i16 @llvm.bswap.i16(i16 %_16.i281.i)
  %narrow778.i = add nuw i8 %8, %narrow.i.i
  %12 = zext i8 %narrow778.i to i64
  %13 = getelementptr inbounds nuw i8, ptr %_42.i92.i, i64 13
  %14 = load i8, ptr %13, align 1, !noalias !16, !noundef !12
  br label %bb11.i101.i

bb11.i101.i:                                      ; preds = %bb10.i100.i, %bb17.i277.i
  %src_port.sroa.0.0.i102.i = phi i16 [ %9, %bb17.i277.i ], [ %91, %bb10.i100.i ]
  %dst_port.sroa.0.0.i103.i = phi i16 [ %11, %bb17.i277.i ], [ %92, %bb10.i100.i ]
  %payload_off.sroa.0.0.i104.i = phi i64 [ %12, %bb17.i277.i ], [ %93, %bb10.i100.i ]
  %flags.sroa.0.0.i105.i = phi i8 [ %14, %bb17.i277.i ], [ 0, %bb10.i100.i ]
  call void @llvm.lifetime.start.p0(ptr nonnull %key.i81.i), !noalias !16
  store i32 %src_ip.i.i, ptr %key.i81.i, align 4, !noalias !16
  %15 = getelementptr inbounds nuw i8, ptr %key.i81.i, i64 4
  store i32 %dst_ip.i.i, ptr %15, align 4, !noalias !16
  %16 = getelementptr inbounds nuw i8, ptr %key.i81.i, i64 8
  store i16 %src_port.sroa.0.0.i102.i, ptr %16, align 4, !noalias !16
  %17 = getelementptr inbounds nuw i8, ptr %key.i81.i, i64 10
  store i16 %dst_port.sroa.0.0.i103.i, ptr %17, align 2, !noalias !16
  %18 = getelementptr inbounds nuw i8, ptr %key.i81.i, i64 12
  store i8 %protocol.i.i, ptr %18, align 4, !noalias !16
  %19 = getelementptr inbounds nuw i8, ptr %key.i81.i, i64 13
  store i8 0, ptr %19, align 1, !noalias !16
  %_33.sroa.4.0..sroa_idx.i108.i = getelementptr inbounds nuw i8, ptr %key.i81.i, i64 14
  store i8 0, ptr %_33.sroa.4.0..sroa_idx.i108.i, align 2, !noalias !16
  %_33.sroa.5.0..sroa_idx.i109.i = getelementptr inbounds nuw i8, ptr %key.i81.i, i64 15
  store i8 0, ptr %_33.sroa.5.0..sroa_idx.i109.i, align 1, !noalias !16
  %_0.i1 = call noundef ptr inttoptr (i64 1 to ptr)(ptr noundef nonnull @FLOW_METRICS, ptr noundef nonnull readonly align 4 dereferenceable(16) %key.i81.i) #5, !noalias !20
  %_20.i.i112.i = icmp eq ptr %_0.i1, null
  br i1 %_20.i.i112.i, label %bb10.i.i144.i, label %bb11.i.i113.i

bb11.i.i113.i:                                    ; preds = %bb11.i101.i
  %20 = getelementptr inbounds nuw i8, ptr %_0.i1, i64 8
  %21 = load <2 x i64>, ptr %_0.i1, align 8, !noalias !20
  %22 = insertelement <2 x i64> <i64 poison, i64 1>, i64 %_19.i.i, i64 0
  %23 = add <2 x i64> %21, %22
  %24 = extractelement <2 x i64> %23, i64 0
  store i64 %24, ptr %_0.i1, align 8, !noalias !20
  %25 = extractelement <2 x i64> %23, i64 1
  store i64 %25, ptr %20, align 8, !noalias !20
  %26 = getelementptr inbounds nuw i8, ptr %_0.i1, i64 16
  %27 = load i8, ptr %26, align 8, !noalias !20, !noundef !12
  %28 = or i8 %27, %flags.sroa.0.0.i105.i
  store i8 %28, ptr %26, align 8, !noalias !20
  %29 = icmp eq i16 %dst_port.sroa.0.0.i103.i, 443
  %or.cond.i.i114.i = and i1 %5, %29
  br i1 %or.cond.i.i114.i, label %bb2.i.i117.i, label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i115.i

bb10.i.i144.i:                                    ; preds = %bb11.i101.i
  call void @llvm.lifetime.start.p0(ptr nonnull %fresh.i.i80.i), !noalias !23
  store i64 %_19.i.i, ptr %fresh.i.i80.i, align 8, !noalias !23
  %_31.i.i78.sroa.4.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 8
  store i64 1, ptr %_31.i.i78.sroa.4.0.fresh.i.i80.sroa_idx.i, align 8, !noalias !23
  %_31.i.i78.sroa.5.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 16
  store i8 %flags.sroa.0.0.i105.i, ptr %_31.i.i78.sroa.5.0.fresh.i.i80.sroa_idx.i, align 8, !noalias !23
  %_31.i.i78.sroa.6.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 17
  store i8 0, ptr %_31.i.i78.sroa.6.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !23
  %_31.i.i78.sroa.7.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 18
  store i16 0, ptr %_31.i.i78.sroa.7.0.fresh.i.i80.sroa_idx.i, align 2, !noalias !23
  %_31.i.i78.sroa.8.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 20
  store i32 0, ptr %_31.i.i78.sroa.8.0.fresh.i.i80.sroa_idx.i, align 4, !noalias !23
  %_31.i.i78.sroa.9.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 24
  store i8 0, ptr %_31.i.i78.sroa.9.0.fresh.i.i80.sroa_idx.i, align 8, !noalias !23
  %_31.i.i78.sroa.10.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 25
  store i8 0, ptr %_31.i.i78.sroa.10.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !23
  %_31.i.i78.sroa.11.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 26
  store i8 0, ptr %_31.i.i78.sroa.11.0.fresh.i.i80.sroa_idx.i, align 2, !noalias !23
  %_31.i.i78.sroa.12.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 27
  store i8 0, ptr %_31.i.i78.sroa.12.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !23
  %_31.i.i78.sroa.13.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 28
  store i8 0, ptr %_31.i.i78.sroa.13.0.fresh.i.i80.sroa_idx.i, align 4, !noalias !23
  %_31.i.i78.sroa.14.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 29
  store i8 0, ptr %_31.i.i78.sroa.14.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !23
  %_31.i.i78.sroa.15.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 30
  store i8 0, ptr %_31.i.i78.sroa.15.0.fresh.i.i80.sroa_idx.i, align 2, !noalias !23
  %_31.i.i78.sroa.16.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 31
  store i8 0, ptr %_31.i.i78.sroa.16.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !23
  %_31.i.i78.sroa.17.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 32
  store i8 0, ptr %_31.i.i78.sroa.17.0.fresh.i.i80.sroa_idx.i, align 8, !noalias !23
  %_31.i.i78.sroa.18.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 33
  store i8 0, ptr %_31.i.i78.sroa.18.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !23
  %_31.i.i78.sroa.19.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 34
  store i8 0, ptr %_31.i.i78.sroa.19.0.fresh.i.i80.sroa_idx.i, align 2, !noalias !23
  %_31.i.i78.sroa.20.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 35
  store i8 0, ptr %_31.i.i78.sroa.20.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !23
  %_31.i.i78.sroa.21.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 36
  store i8 0, ptr %_31.i.i78.sroa.21.0.fresh.i.i80.sroa_idx.i, align 4, !noalias !23
  %_31.i.i78.sroa.22.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 37
  store i8 0, ptr %_31.i.i78.sroa.22.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !23
  %_31.i.i78.sroa.23.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 38
  store i8 0, ptr %_31.i.i78.sroa.23.0.fresh.i.i80.sroa_idx.i, align 2, !noalias !23
  %_31.i.i78.sroa.24.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 39
  store i8 0, ptr %_31.i.i78.sroa.24.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !23
  %_31.i.i78.sroa.25.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 40
  store i8 0, ptr %_31.i.i78.sroa.25.0.fresh.i.i80.sroa_idx.i, align 8, !noalias !23
  %_31.i.i78.sroa.26.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 41
  store i8 0, ptr %_31.i.i78.sroa.26.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !23
  %_31.i.i78.sroa.27.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 42
  store i8 0, ptr %_31.i.i78.sroa.27.0.fresh.i.i80.sroa_idx.i, align 2, !noalias !23
  %_31.i.i78.sroa.28.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 43
  store i8 0, ptr %_31.i.i78.sroa.28.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !23
  %_31.i.i78.sroa.29.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 44
  store i8 0, ptr %_31.i.i78.sroa.29.0.fresh.i.i80.sroa_idx.i, align 4, !noalias !23
  %_31.i.i78.sroa.30.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 45
  store i8 0, ptr %_31.i.i78.sroa.30.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !23
  %_31.i.i78.sroa.31.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 46
  store i8 0, ptr %_31.i.i78.sroa.31.0.fresh.i.i80.sroa_idx.i, align 2, !noalias !23
  %_31.i.i78.sroa.32.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 47
  store i8 0, ptr %_31.i.i78.sroa.32.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !23
  %_31.i.i78.sroa.33.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 48
  store i8 0, ptr %_31.i.i78.sroa.33.0.fresh.i.i80.sroa_idx.i, align 8, !noalias !23
  %_31.i.i78.sroa.34.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 49
  store i8 0, ptr %_31.i.i78.sroa.34.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !23
  %_31.i.i78.sroa.35.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 50
  store i8 0, ptr %_31.i.i78.sroa.35.0.fresh.i.i80.sroa_idx.i, align 2, !noalias !23
  %_31.i.i78.sroa.36.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 51
  store i8 0, ptr %_31.i.i78.sroa.36.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !23
  %_31.i.i78.sroa.37.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 52
  store i8 0, ptr %_31.i.i78.sroa.37.0.fresh.i.i80.sroa_idx.i, align 4, !noalias !23
  %_31.i.i78.sroa.38.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 53
  store i8 0, ptr %_31.i.i78.sroa.38.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !23
  %_31.i.i78.sroa.39.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 54
  store i8 0, ptr %_31.i.i78.sroa.39.0.fresh.i.i80.sroa_idx.i, align 2, !noalias !23
  %_31.i.i78.sroa.40.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 55
  store i8 0, ptr %_31.i.i78.sroa.40.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !23
  %_31.i.i78.sroa.41.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 56
  store i8 0, ptr %_31.i.i78.sroa.41.0.fresh.i.i80.sroa_idx.i, align 8, !noalias !23
  %_31.i.i78.sroa.42.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 57
  store i8 0, ptr %_31.i.i78.sroa.42.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !23
  %_31.i.i78.sroa.43.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 58
  store i8 0, ptr %_31.i.i78.sroa.43.0.fresh.i.i80.sroa_idx.i, align 2, !noalias !23
  %_31.i.i78.sroa.44.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 59
  store i8 0, ptr %_31.i.i78.sroa.44.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !23
  %_31.i.i78.sroa.45.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 60
  store i8 0, ptr %_31.i.i78.sroa.45.0.fresh.i.i80.sroa_idx.i, align 4, !noalias !23
  %_31.i.i78.sroa.46.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 61
  store i8 0, ptr %_31.i.i78.sroa.46.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !23
  %_31.i.i78.sroa.47.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 62
  store i8 0, ptr %_31.i.i78.sroa.47.0.fresh.i.i80.sroa_idx.i, align 2, !noalias !23
  %_31.i.i78.sroa.48.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 63
  store i8 0, ptr %_31.i.i78.sroa.48.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !23
  %_31.i.i78.sroa.49.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 64
  store i8 0, ptr %_31.i.i78.sroa.49.0.fresh.i.i80.sroa_idx.i, align 8, !noalias !23
  %_31.i.i78.sroa.50.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 65
  store i8 0, ptr %_31.i.i78.sroa.50.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !23
  %_31.i.i78.sroa.51.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 66
  store i8 0, ptr %_31.i.i78.sroa.51.0.fresh.i.i80.sroa_idx.i, align 2, !noalias !23
  %_31.i.i78.sroa.52.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 67
  store i8 0, ptr %_31.i.i78.sroa.52.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !23
  %_31.i.i78.sroa.53.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 68
  store i8 0, ptr %_31.i.i78.sroa.53.0.fresh.i.i80.sroa_idx.i, align 4, !noalias !23
  %_31.i.i78.sroa.54.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 69
  store i8 0, ptr %_31.i.i78.sroa.54.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !23
  %_31.i.i78.sroa.55.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 70
  store i8 0, ptr %_31.i.i78.sroa.55.0.fresh.i.i80.sroa_idx.i, align 2, !noalias !23
  %_31.i.i78.sroa.56.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 71
  store i8 0, ptr %_31.i.i78.sroa.56.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !23
  %_31.i.i78.sroa.57.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 72
  store i8 0, ptr %_31.i.i78.sroa.57.0.fresh.i.i80.sroa_idx.i, align 8, !noalias !23
  %_31.i.i78.sroa.58.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 73
  store i8 0, ptr %_31.i.i78.sroa.58.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !23
  %_31.i.i78.sroa.59.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 74
  store i8 0, ptr %_31.i.i78.sroa.59.0.fresh.i.i80.sroa_idx.i, align 2, !noalias !23
  %_31.i.i78.sroa.60.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 75
  store i8 0, ptr %_31.i.i78.sroa.60.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !23
  %_31.i.i78.sroa.61.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 76
  store i8 0, ptr %_31.i.i78.sroa.61.0.fresh.i.i80.sroa_idx.i, align 4, !noalias !23
  %_31.i.i78.sroa.62.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 77
  store i8 0, ptr %_31.i.i78.sroa.62.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !23
  %_31.i.i78.sroa.63.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 78
  store i8 0, ptr %_31.i.i78.sroa.63.0.fresh.i.i80.sroa_idx.i, align 2, !noalias !23
  %_31.i.i78.sroa.64.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 79
  store i8 0, ptr %_31.i.i78.sroa.64.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !23
  %_31.i.i78.sroa.65.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 80
  store i8 0, ptr %_31.i.i78.sroa.65.0.fresh.i.i80.sroa_idx.i, align 8, !noalias !23
  %_31.i.i78.sroa.66.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 81
  store i8 0, ptr %_31.i.i78.sroa.66.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !23
  %_31.i.i78.sroa.67.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 82
  store i8 0, ptr %_31.i.i78.sroa.67.0.fresh.i.i80.sroa_idx.i, align 2, !noalias !23
  %_31.i.i78.sroa.68.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 83
  store i8 0, ptr %_31.i.i78.sroa.68.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !23
  %_31.i.i78.sroa.69.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 84
  store i8 0, ptr %_31.i.i78.sroa.69.0.fresh.i.i80.sroa_idx.i, align 4, !noalias !23
  %_31.i.i78.sroa.70.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 85
  store i8 0, ptr %_31.i.i78.sroa.70.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !23
  %_31.i.i78.sroa.71.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 86
  store i8 0, ptr %_31.i.i78.sroa.71.0.fresh.i.i80.sroa_idx.i, align 2, !noalias !23
  %_31.i.i78.sroa.72.0.fresh.i.i80.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i80.i, i64 87
  store i8 0, ptr %_31.i.i78.sroa.72.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !23
  %30 = icmp eq i16 %dst_port.sroa.0.0.i103.i, 443
  %or.cond1.i.i149.i = and i1 %5, %30
  br i1 %or.cond1.i.i149.i, label %bb5.i.i152.i, label %bb7.i.i150.i

bb2.i.i117.i:                                     ; preds = %bb11.i.i113.i
  %_28.i5.i.i119.i = load i32, ptr %ctx, align 4, !noalias !25, !noundef !12
  %_22.i6.i.i120.i = zext i32 %_28.i5.i.i119.i to i64
  %_21.i7.i.i121.i = inttoptr i64 %_22.i6.i.i120.i to ptr
  %_30.i8.i.i122.i = load i32, ptr %0, align 4, !noalias !25, !noundef !12
  %_24.i9.i.i123.i = zext i32 %_30.i8.i.i122.i to i64
  %_23.i10.i.i124.i = inttoptr i64 %_24.i9.i.i123.i to ptr
  %_25.i11.i.i125.i = getelementptr inbounds nuw i8, ptr %_21.i7.i.i121.i, i64 %payload_off.sroa.0.0.i104.i
  %_27.i12.i.i126.i = getelementptr inbounds nuw i8, ptr %_25.i11.i.i125.i, i64 1
  %_26.i13.i.i127.i = icmp ugt ptr %_27.i12.i.i126.i, %_23.i10.i.i124.i
  br i1 %_26.i13.i.i127.i, label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i115.i, label %bb10.i14.i.i128.i

bb10.i14.i.i128.i:                                ; preds = %bb2.i.i117.i
  %_6.i15.i.i129.i = load i8, ptr %_25.i11.i.i125.i, align 1, !noalias !25, !noundef !12
  %31 = icmp ne i8 %_6.i15.i.i129.i, 22
  %_39.i17.i.i132.i = getelementptr i8, ptr %_25.i11.i.i125.i, i64 21
  %_38.i18.i.i133.i = icmp ugt ptr %_39.i17.i.i132.i, %_23.i10.i.i124.i
  %or.cond.i = or i1 %_38.i18.i.i133.i, %31
  br i1 %or.cond.i, label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i115.i, label %bb12.i19.i.i134.i

bb12.i19.i.i134.i:                                ; preds = %bb10.i14.i.i128.i
  %_37.i20.i.i135.i = getelementptr i8, ptr %_25.i11.i.i125.i, i64 5
  %_13.i21.i.i136.i = getelementptr inbounds nuw i8, ptr %_0.i1, i64 24
  call void @llvm.memcpy.p0.p0.i64(ptr noundef nonnull align 1 dereferenceable(16) %_13.i21.i.i136.i, ptr noundef nonnull align 1 dereferenceable(16) %_37.i20.i.i135.i, i64 16, i1 false), !noalias !25
  %32 = getelementptr inbounds nuw i8, ptr %_0.i1, i64 25
  %33 = getelementptr inbounds nuw i8, ptr %_0.i1, i64 26
  %34 = getelementptr inbounds nuw i8, ptr %_0.i1, i64 27
  %35 = getelementptr inbounds nuw i8, ptr %_0.i1, i64 28
  %36 = getelementptr inbounds nuw i8, ptr %_0.i1, i64 29
  %37 = getelementptr inbounds nuw i8, ptr %_0.i1, i64 30
  %38 = getelementptr inbounds nuw i8, ptr %_0.i1, i64 31
  %39 = getelementptr inbounds nuw i8, ptr %_0.i1, i64 32
  %40 = getelementptr inbounds nuw i8, ptr %_0.i1, i64 33
  %41 = getelementptr inbounds nuw i8, ptr %_0.i1, i64 34
  %42 = getelementptr inbounds nuw i8, ptr %_0.i1, i64 35
  %43 = getelementptr inbounds nuw i8, ptr %_0.i1, i64 36
  %44 = getelementptr inbounds nuw i8, ptr %_0.i1, i64 37
  %45 = getelementptr inbounds nuw i8, ptr %_0.i1, i64 38
  %46 = getelementptr inbounds nuw i8, ptr %_0.i1, i64 39
  %47 = load <16 x i8>, ptr %_13.i21.i.i136.i, align 8, !noalias !25
  %48 = add <16 x i8> %47, splat (i8 -32)
  %49 = icmp ult <16 x i8> %48, splat (i8 95)
  %50 = select <16 x i1> %49, <16 x i8> %47, <16 x i8> zeroinitializer
  %51 = extractelement <16 x i8> %50, i64 0
  store i8 %51, ptr %_13.i21.i.i136.i, align 8, !noalias !25
  %52 = extractelement <16 x i8> %50, i64 1
  store i8 %52, ptr %32, align 1, !noalias !25
  %53 = extractelement <16 x i8> %50, i64 2
  store i8 %53, ptr %33, align 2, !noalias !25
  %54 = extractelement <16 x i8> %50, i64 3
  store i8 %54, ptr %34, align 1, !noalias !25
  %55 = extractelement <16 x i8> %50, i64 4
  store i8 %55, ptr %35, align 4, !noalias !25
  %56 = extractelement <16 x i8> %50, i64 5
  store i8 %56, ptr %36, align 1, !noalias !25
  %57 = extractelement <16 x i8> %50, i64 6
  store i8 %57, ptr %37, align 2, !noalias !25
  %58 = extractelement <16 x i8> %50, i64 7
  store i8 %58, ptr %38, align 1, !noalias !25
  %59 = extractelement <16 x i8> %50, i64 8
  store i8 %59, ptr %39, align 8, !noalias !25
  %60 = extractelement <16 x i8> %50, i64 9
  store i8 %60, ptr %40, align 1, !noalias !25
  %61 = extractelement <16 x i8> %50, i64 10
  store i8 %61, ptr %41, align 2, !noalias !25
  %62 = extractelement <16 x i8> %50, i64 11
  store i8 %62, ptr %42, align 1, !noalias !25
  %63 = extractelement <16 x i8> %50, i64 12
  store i8 %63, ptr %43, align 4, !noalias !25
  %64 = extractelement <16 x i8> %50, i64 13
  store i8 %64, ptr %44, align 1, !noalias !25
  %65 = extractelement <16 x i8> %50, i64 14
  store i8 %65, ptr %45, align 2, !noalias !25
  %66 = extractelement <16 x i8> %50, i64 15
  store i8 %66, ptr %46, align 1, !noalias !25
  br label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i115.i

bb7.i.i150.i:                                     ; preds = %bb12.i.i.i169.i, %bb10.i.i.i163.i, %bb5.i.i152.i, %bb10.i.i144.i
  %_0.i2 = call noundef i64 inttoptr (i64 2 to ptr)(ptr noundef nonnull @FLOW_METRICS, ptr noundef nonnull readonly align 4 dereferenceable(16) %key.i81.i, ptr noundef nonnull %fresh.i.i80.i, i64 noundef 0) #5
  call void @llvm.lifetime.end.p0(ptr nonnull %fresh.i.i80.i), !noalias !23
  br label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i115.i

bb5.i.i152.i:                                     ; preds = %bb10.i.i144.i
  %_28.i.i.i154.i = load i32, ptr %ctx, align 4, !noalias !28, !noundef !12
  %_22.i.i.i155.i = zext i32 %_28.i.i.i154.i to i64
  %_21.i.i.i156.i = inttoptr i64 %_22.i.i.i155.i to ptr
  %_30.i.i.i157.i = load i32, ptr %0, align 4, !noalias !28, !noundef !12
  %_24.i.i.i158.i = zext i32 %_30.i.i.i157.i to i64
  %_23.i.i.i159.i = inttoptr i64 %_24.i.i.i158.i to ptr
  %_25.i.i.i160.i = getelementptr inbounds nuw i8, ptr %_21.i.i.i156.i, i64 %payload_off.sroa.0.0.i104.i
  %_27.i.i.i161.i = getelementptr inbounds nuw i8, ptr %_25.i.i.i160.i, i64 1
  %_26.i.i.i162.i = icmp ugt ptr %_27.i.i.i161.i, %_23.i.i.i159.i
  br i1 %_26.i.i.i162.i, label %bb7.i.i150.i, label %bb10.i.i.i163.i

bb10.i.i.i163.i:                                  ; preds = %bb5.i.i152.i
  %_6.i.i.i164.i = load i8, ptr %_25.i.i.i160.i, align 1, !noalias !28, !noundef !12
  %67 = icmp ne i8 %_6.i.i.i164.i, 22
  %_39.i.i.i167.i = getelementptr i8, ptr %_25.i.i.i160.i, i64 21
  %_38.i.i.i168.i = icmp ugt ptr %_39.i.i.i167.i, %_23.i.i.i159.i
  %or.cond765.i = or i1 %_38.i.i.i168.i, %67
  br i1 %or.cond765.i, label %bb7.i.i150.i, label %bb12.i.i.i169.i

bb12.i.i.i169.i:                                  ; preds = %bb10.i.i.i163.i
  %_37.i.i.i170.i = getelementptr i8, ptr %_25.i.i.i160.i, i64 5
  call void @llvm.memcpy.p0.p0.i64(ptr noundef nonnull align 8 dereferenceable(16) %_31.i.i78.sroa.9.0.fresh.i.i80.sroa_idx.i, ptr noundef nonnull align 1 dereferenceable(16) %_37.i.i.i170.i, i64 16, i1 false), !noalias !28
  %68 = load <16 x i8>, ptr %_31.i.i78.sroa.9.0.fresh.i.i80.sroa_idx.i, align 8, !noalias !31
  %69 = add <16 x i8> %68, splat (i8 -32)
  %70 = icmp ult <16 x i8> %69, splat (i8 95)
  %71 = select <16 x i1> %70, <16 x i8> %68, <16 x i8> zeroinitializer
  %72 = extractelement <16 x i8> %71, i64 0
  store i8 %72, ptr %_31.i.i78.sroa.9.0.fresh.i.i80.sroa_idx.i, align 8, !noalias !31
  %73 = extractelement <16 x i8> %71, i64 1
  store i8 %73, ptr %_31.i.i78.sroa.10.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !31
  %74 = extractelement <16 x i8> %71, i64 2
  store i8 %74, ptr %_31.i.i78.sroa.11.0.fresh.i.i80.sroa_idx.i, align 2, !noalias !31
  %75 = extractelement <16 x i8> %71, i64 3
  store i8 %75, ptr %_31.i.i78.sroa.12.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !31
  %76 = extractelement <16 x i8> %71, i64 4
  store i8 %76, ptr %_31.i.i78.sroa.13.0.fresh.i.i80.sroa_idx.i, align 4, !noalias !31
  %77 = extractelement <16 x i8> %71, i64 5
  store i8 %77, ptr %_31.i.i78.sroa.14.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !31
  %78 = extractelement <16 x i8> %71, i64 6
  store i8 %78, ptr %_31.i.i78.sroa.15.0.fresh.i.i80.sroa_idx.i, align 2, !noalias !31
  %79 = extractelement <16 x i8> %71, i64 7
  store i8 %79, ptr %_31.i.i78.sroa.16.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !31
  %80 = extractelement <16 x i8> %71, i64 8
  store i8 %80, ptr %_31.i.i78.sroa.17.0.fresh.i.i80.sroa_idx.i, align 8, !noalias !31
  %81 = extractelement <16 x i8> %71, i64 9
  store i8 %81, ptr %_31.i.i78.sroa.18.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !31
  %82 = extractelement <16 x i8> %71, i64 10
  store i8 %82, ptr %_31.i.i78.sroa.19.0.fresh.i.i80.sroa_idx.i, align 2, !noalias !31
  %83 = extractelement <16 x i8> %71, i64 11
  store i8 %83, ptr %_31.i.i78.sroa.20.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !31
  %84 = extractelement <16 x i8> %71, i64 12
  store i8 %84, ptr %_31.i.i78.sroa.21.0.fresh.i.i80.sroa_idx.i, align 4, !noalias !31
  %85 = extractelement <16 x i8> %71, i64 13
  store i8 %85, ptr %_31.i.i78.sroa.22.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !31
  %86 = extractelement <16 x i8> %71, i64 14
  store i8 %86, ptr %_31.i.i78.sroa.23.0.fresh.i.i80.sroa_idx.i, align 2, !noalias !31
  %87 = extractelement <16 x i8> %71, i64 15
  store i8 %87, ptr %_31.i.i78.sroa.24.0.fresh.i.i80.sroa_idx.i, align 1, !noalias !31
  br label %bb7.i.i150.i

_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i115.i: ; preds = %bb7.i.i150.i, %bb12.i19.i.i134.i, %bb10.i14.i.i128.i, %bb2.i.i117.i, %bb11.i.i113.i
  call void @llvm.lifetime.end.p0(ptr nonnull %key.i81.i), !noalias !16
  br label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv410parse_ipv4.exit.i

bb21.i96.i:                                       ; preds = %bb3.i93.i
  %_24.i97.i = load i16, ptr %_42.i92.i, align 2, !noalias !16, !noundef !12
  %88 = getelementptr inbounds nuw i8, ptr %_42.i92.i, i64 2
  %_25.i98.i = load i16, ptr %88, align 2, !noalias !16, !noundef !12
  %89 = icmp eq i16 %_25.i98.i, -19182
  %90 = icmp eq i16 %_24.i97.i, -19182
  %or.cond.i99.i = or i1 %90, %89
  br i1 %or.cond.i99.i, label %bb5.i180.i, label %bb10.i100.i

bb5.i180.i:                                       ; preds = %bb21.i96.i
  %_21.i289.i = getelementptr i8, ptr %_42.i92.i, i64 30
  %_20.i290.i = icmp samesign ugt ptr %_21.i289.i, %_39.i91.i
  br i1 %_20.i290.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv410parse_ipv4.exit.i, label %bb7.i183.i

bb10.i100.i:                                      ; preds = %bb21.i96.i
  %91 = tail call i16 @llvm.bswap.i16(i16 %_24.i97.i)
  %92 = tail call i16 @llvm.bswap.i16(i16 %_25.i98.i)
  %93 = add nuw nsw i64 %xport_off.i.i, 8
  br label %bb11.i101.i

bb7.i183.i:                                       ; preds = %bb5.i180.i
  %94 = getelementptr i8, ptr %_42.i92.i, i64 28
  %_11.i292.i = load i16, ptr %94, align 2, !noalias !32, !noundef !12
  %etype.i293.i = tail call i16 @llvm.bswap.i16(i16 %_11.i292.i)
  %_13.i294.i = add nuw nsw i64 %xport_off.i.i, 30
  switch i16 %etype.i293.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv410parse_ipv4.exit.i [
    i16 2048, label %bb3.i.i245.i
    i16 -31011, label %bb2.i6.i186.i
  ]

bb3.i.i245.i:                                     ; preds = %bb7.i183.i
  %_61.i.i253.i = getelementptr inbounds nuw i8, ptr %_37.i88.i, i64 %_13.i294.i
  %_63.i.i254.i = getelementptr inbounds nuw i8, ptr %_61.i.i253.i, i64 20
  %_62.i.i255.i = icmp samesign ugt ptr %_63.i.i254.i, %_39.i91.i
  br i1 %_62.i.i255.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv410parse_ipv4.exit.i, label %bb10.i10.i256.i

bb2.i6.i186.i:                                    ; preds = %bb7.i183.i
  %_49.i.i194.i = getelementptr inbounds nuw i8, ptr %_37.i88.i, i64 %_13.i294.i
  %_51.i.i195.i = getelementptr inbounds nuw i8, ptr %_49.i.i194.i, i64 40
  %_50.i.i196.i = icmp samesign ugt ptr %_51.i.i195.i, %_39.i91.i
  br i1 %_50.i.i196.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv410parse_ipv4.exit.i, label %bb8.i.i197.i

bb10.i10.i256.i:                                  ; preds = %bb3.i.i245.i
  %_73.i.i257.i = getelementptr inbounds nuw i8, ptr %_61.i.i253.i, i64 12
  %_0.i3 = tail call noundef ptr inttoptr (i64 1 to ptr)(ptr noundef nonnull @BLOCKLIST, ptr noundef nonnull %_73.i.i257.i) #5, !noalias !36
  %_74.i.i259.i = icmp eq ptr %_0.i3, null
  br i1 %_74.i.i259.i, label %bb12.i11.i260.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv410parse_ipv4.exit.i

bb12.i11.i260.i:                                  ; preds = %bb10.i10.i256.i
  %95 = getelementptr inbounds nuw i8, ptr %_61.i.i253.i, i64 9
  %proto.i.i261.i = load i8, ptr %95, align 1, !noalias !36, !noundef !12
  %_13.i.i262.i = load i8, ptr %_61.i.i253.i, align 4, !noalias !36, !noundef !12
  %_12.i.i263.i = shl i8 %_13.i.i262.i, 2
  %96 = and i8 %_12.i.i263.i, 60
  %ihl.i.i264.i = zext nneg i8 %96 to i64
  %xoff.i.i265.i = add nuw nsw i64 %_13.i294.i, %ihl.i.i264.i
  %_78.i.i267.i = load i32, ptr %0, align 4, !noalias !36, !noundef !12
  %_17.i.i268.i = zext i32 %_78.i.i267.i to i64
  %_80.i.i269.i = load i32, ptr %ctx, align 4, !noalias !36, !noundef !12
  %_18.i.i270.i = zext i32 %_80.i.i269.i to i64
  %_16.i12.i271.i = sub nsw i64 %_17.i.i268.i, %_18.i.i270.i
  %_19.i.i272.i = load i32, ptr %_73.i.i257.i, align 4, !noalias !36, !noundef !12
  %97 = getelementptr inbounds nuw i8, ptr %_61.i.i253.i, i64 16
  %_20.i13.i273.i = load i32, ptr %97, align 4, !noalias !36, !noundef !12
  switch i8 %proto.i.i261.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv410parse_ipv4.exit.i [
    i8 6, label %bb4.i402.i
    i8 17, label %bb5.i316.i
  ]

bb4.i402.i:                                       ; preds = %bb12.i11.i260.i
  %_31.i406.i = inttoptr i64 %_18.i.i270.i to ptr
  %_33.i.i = inttoptr i64 %_17.i.i268.i to ptr
  %_36.i408.i = getelementptr inbounds nuw i8, ptr %_31.i406.i, i64 %xoff.i.i265.i
  %_38.i409.i = getelementptr inbounds nuw i8, ptr %_36.i408.i, i64 20
  %_37.i410.i = icmp samesign ugt ptr %_38.i409.i, %_33.i.i
  br i1 %_37.i410.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv410parse_ipv4.exit.i, label %bb11.i411.i

bb5.i316.i:                                       ; preds = %bb12.i11.i260.i
  %_43.i320.i = inttoptr i64 %_18.i.i270.i to ptr
  %_45.i323.i = inttoptr i64 %_17.i.i268.i to ptr
  %_48.i324.i = getelementptr inbounds nuw i8, ptr %_43.i320.i, i64 %xoff.i.i265.i
  %_50.i325.i = getelementptr inbounds nuw i8, ptr %_48.i324.i, i64 8
  %_49.i326.i = icmp samesign ugt ptr %_50.i325.i, %_45.i323.i
  br i1 %_49.i326.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv410parse_ipv4.exit.i, label %bb13.i327.i

bb11.i411.i:                                      ; preds = %bb4.i402.i
  %98 = getelementptr inbounds nuw i8, ptr %_36.i408.i, i64 12
  %_14.i412.i = load i8, ptr %98, align 4, !noalias !39, !noundef !12
  %99 = lshr i8 %_14.i412.i, 2
  %100 = and i8 %99, 60
  %thlen.i413.i = zext nneg i8 %100 to i64
  %_15.i414.i = load i16, ptr %_36.i408.i, align 4, !noalias !39, !noundef !12
  %101 = tail call i16 @llvm.bswap.i16(i16 %_15.i414.i)
  %102 = getelementptr inbounds nuw i8, ptr %_36.i408.i, i64 2
  %_16.i415.i = load i16, ptr %102, align 2, !noalias !39, !noundef !12
  %103 = tail call i16 @llvm.bswap.i16(i16 %_16.i415.i)
  %104 = getelementptr inbounds nuw i8, ptr %_36.i408.i, i64 13
  %105 = load i8, ptr %104, align 1, !noalias !39, !noundef !12
  br label %bb6.i.i

bb6.i.i:                                          ; preds = %bb13.i327.i, %bb11.i411.i
  %flags.sroa.0.0.i330.i = phi i8 [ %105, %bb11.i411.i ], [ 0, %bb13.i327.i ]
  %sp.sroa.0.0.i.i = phi i16 [ %101, %bb11.i411.i ], [ %181, %bb13.i327.i ]
  %dp.sroa.0.0.i.i = phi i16 [ %103, %bb11.i411.i ], [ %183, %bb13.i327.i ]
  %thlen.pn.i.i = phi i64 [ %thlen.i413.i, %bb11.i411.i ], [ 8, %bb13.i327.i ]
  %payload_off.sroa.0.0.i331.i = add nuw nsw i64 %thlen.pn.i.i, %xoff.i.i265.i
  call void @llvm.lifetime.start.p0(ptr nonnull %key.i315.i), !noalias !39
  store i32 %_19.i.i272.i, ptr %key.i315.i, align 4, !noalias !39
  %106 = getelementptr inbounds nuw i8, ptr %key.i315.i, i64 4
  store i32 %_20.i13.i273.i, ptr %106, align 4, !noalias !39
  %107 = getelementptr inbounds nuw i8, ptr %key.i315.i, i64 8
  store i16 %sp.sroa.0.0.i.i, ptr %107, align 4, !noalias !39
  %108 = getelementptr inbounds nuw i8, ptr %key.i315.i, i64 10
  store i16 %dp.sroa.0.0.i.i, ptr %108, align 2, !noalias !39
  %109 = getelementptr inbounds nuw i8, ptr %key.i315.i, i64 12
  store i8 %proto.i.i261.i, ptr %109, align 4, !noalias !39
  %110 = getelementptr inbounds nuw i8, ptr %key.i315.i, i64 13
  store i8 0, ptr %110, align 1, !noalias !39
  %_28.sroa.4.0..sroa_idx.i.i = getelementptr inbounds nuw i8, ptr %key.i315.i, i64 14
  store i8 0, ptr %_28.sroa.4.0..sroa_idx.i.i, align 2, !noalias !39
  %_28.sroa.5.0..sroa_idx.i.i = getelementptr inbounds nuw i8, ptr %key.i315.i, i64 15
  store i8 0, ptr %_28.sroa.5.0..sroa_idx.i.i, align 1, !noalias !39
  %_0.i4 = call noundef ptr inttoptr (i64 1 to ptr)(ptr noundef nonnull @FLOW_METRICS, ptr noundef nonnull readonly align 4 dereferenceable(16) %key.i315.i) #5, !noalias !42
  %_20.i.i333.i = icmp eq ptr %_0.i4, null
  br i1 %_20.i.i333.i, label %bb10.i.i366.i, label %bb11.i.i334.i

bb11.i.i334.i:                                    ; preds = %bb6.i.i
  %111 = getelementptr inbounds nuw i8, ptr %_0.i4, i64 8
  %112 = load <2 x i64>, ptr %_0.i4, align 8, !noalias !42
  %113 = insertelement <2 x i64> <i64 poison, i64 1>, i64 %_16.i12.i271.i, i64 0
  %114 = add <2 x i64> %112, %113
  %115 = extractelement <2 x i64> %114, i64 0
  store i64 %115, ptr %_0.i4, align 8, !noalias !42
  %116 = extractelement <2 x i64> %114, i64 1
  store i64 %116, ptr %111, align 8, !noalias !42
  %117 = getelementptr inbounds nuw i8, ptr %_0.i4, i64 16
  %118 = load i8, ptr %117, align 8, !noalias !42, !noundef !12
  %119 = or i8 %118, %flags.sroa.0.0.i330.i
  store i8 %119, ptr %117, align 8, !noalias !42
  %120 = icmp eq i8 %proto.i.i261.i, 6
  %121 = icmp eq i16 %dp.sroa.0.0.i.i, 443
  %or.cond.i.i335.i = and i1 %120, %121
  br i1 %or.cond.i.i335.i, label %bb2.i.i339.i, label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i336.i

bb10.i.i366.i:                                    ; preds = %bb6.i.i
  call void @llvm.lifetime.start.p0(ptr nonnull %fresh.i.i314.i), !noalias !45
  store i64 %_16.i12.i271.i, ptr %fresh.i.i314.i, align 8, !noalias !45
  %_31.i.i312.sroa.4.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 8
  store i64 1, ptr %_31.i.i312.sroa.4.0.fresh.i.i314.sroa_idx.i, align 8, !noalias !45
  %_31.i.i312.sroa.5.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 16
  store i8 %flags.sroa.0.0.i330.i, ptr %_31.i.i312.sroa.5.0.fresh.i.i314.sroa_idx.i, align 8, !noalias !45
  %_31.i.i312.sroa.6.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 17
  store i8 0, ptr %_31.i.i312.sroa.6.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !45
  %_31.i.i312.sroa.7.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 18
  store i16 0, ptr %_31.i.i312.sroa.7.0.fresh.i.i314.sroa_idx.i, align 2, !noalias !45
  %_31.i.i312.sroa.8.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 20
  store i32 0, ptr %_31.i.i312.sroa.8.0.fresh.i.i314.sroa_idx.i, align 4, !noalias !45
  %_31.i.i312.sroa.9.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 24
  store i8 0, ptr %_31.i.i312.sroa.9.0.fresh.i.i314.sroa_idx.i, align 8, !noalias !45
  %_31.i.i312.sroa.10.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 25
  store i8 0, ptr %_31.i.i312.sroa.10.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !45
  %_31.i.i312.sroa.11.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 26
  store i8 0, ptr %_31.i.i312.sroa.11.0.fresh.i.i314.sroa_idx.i, align 2, !noalias !45
  %_31.i.i312.sroa.12.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 27
  store i8 0, ptr %_31.i.i312.sroa.12.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !45
  %_31.i.i312.sroa.13.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 28
  store i8 0, ptr %_31.i.i312.sroa.13.0.fresh.i.i314.sroa_idx.i, align 4, !noalias !45
  %_31.i.i312.sroa.14.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 29
  store i8 0, ptr %_31.i.i312.sroa.14.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !45
  %_31.i.i312.sroa.15.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 30
  store i8 0, ptr %_31.i.i312.sroa.15.0.fresh.i.i314.sroa_idx.i, align 2, !noalias !45
  %_31.i.i312.sroa.16.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 31
  store i8 0, ptr %_31.i.i312.sroa.16.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !45
  %_31.i.i312.sroa.17.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 32
  store i8 0, ptr %_31.i.i312.sroa.17.0.fresh.i.i314.sroa_idx.i, align 8, !noalias !45
  %_31.i.i312.sroa.18.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 33
  store i8 0, ptr %_31.i.i312.sroa.18.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !45
  %_31.i.i312.sroa.19.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 34
  store i8 0, ptr %_31.i.i312.sroa.19.0.fresh.i.i314.sroa_idx.i, align 2, !noalias !45
  %_31.i.i312.sroa.20.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 35
  store i8 0, ptr %_31.i.i312.sroa.20.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !45
  %_31.i.i312.sroa.21.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 36
  store i8 0, ptr %_31.i.i312.sroa.21.0.fresh.i.i314.sroa_idx.i, align 4, !noalias !45
  %_31.i.i312.sroa.22.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 37
  store i8 0, ptr %_31.i.i312.sroa.22.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !45
  %_31.i.i312.sroa.23.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 38
  store i8 0, ptr %_31.i.i312.sroa.23.0.fresh.i.i314.sroa_idx.i, align 2, !noalias !45
  %_31.i.i312.sroa.24.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 39
  store i8 0, ptr %_31.i.i312.sroa.24.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !45
  %_31.i.i312.sroa.25.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 40
  store i8 0, ptr %_31.i.i312.sroa.25.0.fresh.i.i314.sroa_idx.i, align 8, !noalias !45
  %_31.i.i312.sroa.26.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 41
  store i8 0, ptr %_31.i.i312.sroa.26.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !45
  %_31.i.i312.sroa.27.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 42
  store i8 0, ptr %_31.i.i312.sroa.27.0.fresh.i.i314.sroa_idx.i, align 2, !noalias !45
  %_31.i.i312.sroa.28.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 43
  store i8 0, ptr %_31.i.i312.sroa.28.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !45
  %_31.i.i312.sroa.29.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 44
  store i8 0, ptr %_31.i.i312.sroa.29.0.fresh.i.i314.sroa_idx.i, align 4, !noalias !45
  %_31.i.i312.sroa.30.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 45
  store i8 0, ptr %_31.i.i312.sroa.30.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !45
  %_31.i.i312.sroa.31.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 46
  store i8 0, ptr %_31.i.i312.sroa.31.0.fresh.i.i314.sroa_idx.i, align 2, !noalias !45
  %_31.i.i312.sroa.32.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 47
  store i8 0, ptr %_31.i.i312.sroa.32.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !45
  %_31.i.i312.sroa.33.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 48
  store i8 0, ptr %_31.i.i312.sroa.33.0.fresh.i.i314.sroa_idx.i, align 8, !noalias !45
  %_31.i.i312.sroa.34.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 49
  store i8 0, ptr %_31.i.i312.sroa.34.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !45
  %_31.i.i312.sroa.35.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 50
  store i8 0, ptr %_31.i.i312.sroa.35.0.fresh.i.i314.sroa_idx.i, align 2, !noalias !45
  %_31.i.i312.sroa.36.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 51
  store i8 0, ptr %_31.i.i312.sroa.36.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !45
  %_31.i.i312.sroa.37.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 52
  store i8 0, ptr %_31.i.i312.sroa.37.0.fresh.i.i314.sroa_idx.i, align 4, !noalias !45
  %_31.i.i312.sroa.38.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 53
  store i8 0, ptr %_31.i.i312.sroa.38.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !45
  %_31.i.i312.sroa.39.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 54
  store i8 0, ptr %_31.i.i312.sroa.39.0.fresh.i.i314.sroa_idx.i, align 2, !noalias !45
  %_31.i.i312.sroa.40.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 55
  store i8 0, ptr %_31.i.i312.sroa.40.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !45
  %_31.i.i312.sroa.41.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 56
  store i8 0, ptr %_31.i.i312.sroa.41.0.fresh.i.i314.sroa_idx.i, align 8, !noalias !45
  %_31.i.i312.sroa.42.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 57
  store i8 0, ptr %_31.i.i312.sroa.42.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !45
  %_31.i.i312.sroa.43.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 58
  store i8 0, ptr %_31.i.i312.sroa.43.0.fresh.i.i314.sroa_idx.i, align 2, !noalias !45
  %_31.i.i312.sroa.44.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 59
  store i8 0, ptr %_31.i.i312.sroa.44.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !45
  %_31.i.i312.sroa.45.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 60
  store i8 0, ptr %_31.i.i312.sroa.45.0.fresh.i.i314.sroa_idx.i, align 4, !noalias !45
  %_31.i.i312.sroa.46.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 61
  store i8 0, ptr %_31.i.i312.sroa.46.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !45
  %_31.i.i312.sroa.47.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 62
  store i8 0, ptr %_31.i.i312.sroa.47.0.fresh.i.i314.sroa_idx.i, align 2, !noalias !45
  %_31.i.i312.sroa.48.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 63
  store i8 0, ptr %_31.i.i312.sroa.48.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !45
  %_31.i.i312.sroa.49.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 64
  store i8 0, ptr %_31.i.i312.sroa.49.0.fresh.i.i314.sroa_idx.i, align 8, !noalias !45
  %_31.i.i312.sroa.50.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 65
  store i8 0, ptr %_31.i.i312.sroa.50.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !45
  %_31.i.i312.sroa.51.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 66
  store i8 0, ptr %_31.i.i312.sroa.51.0.fresh.i.i314.sroa_idx.i, align 2, !noalias !45
  %_31.i.i312.sroa.52.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 67
  store i8 0, ptr %_31.i.i312.sroa.52.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !45
  %_31.i.i312.sroa.53.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 68
  store i8 0, ptr %_31.i.i312.sroa.53.0.fresh.i.i314.sroa_idx.i, align 4, !noalias !45
  %_31.i.i312.sroa.54.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 69
  store i8 0, ptr %_31.i.i312.sroa.54.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !45
  %_31.i.i312.sroa.55.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 70
  store i8 0, ptr %_31.i.i312.sroa.55.0.fresh.i.i314.sroa_idx.i, align 2, !noalias !45
  %_31.i.i312.sroa.56.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 71
  store i8 0, ptr %_31.i.i312.sroa.56.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !45
  %_31.i.i312.sroa.57.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 72
  store i8 0, ptr %_31.i.i312.sroa.57.0.fresh.i.i314.sroa_idx.i, align 8, !noalias !45
  %_31.i.i312.sroa.58.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 73
  store i8 0, ptr %_31.i.i312.sroa.58.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !45
  %_31.i.i312.sroa.59.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 74
  store i8 0, ptr %_31.i.i312.sroa.59.0.fresh.i.i314.sroa_idx.i, align 2, !noalias !45
  %_31.i.i312.sroa.60.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 75
  store i8 0, ptr %_31.i.i312.sroa.60.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !45
  %_31.i.i312.sroa.61.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 76
  store i8 0, ptr %_31.i.i312.sroa.61.0.fresh.i.i314.sroa_idx.i, align 4, !noalias !45
  %_31.i.i312.sroa.62.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 77
  store i8 0, ptr %_31.i.i312.sroa.62.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !45
  %_31.i.i312.sroa.63.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 78
  store i8 0, ptr %_31.i.i312.sroa.63.0.fresh.i.i314.sroa_idx.i, align 2, !noalias !45
  %_31.i.i312.sroa.64.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 79
  store i8 0, ptr %_31.i.i312.sroa.64.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !45
  %_31.i.i312.sroa.65.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 80
  store i8 0, ptr %_31.i.i312.sroa.65.0.fresh.i.i314.sroa_idx.i, align 8, !noalias !45
  %_31.i.i312.sroa.66.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 81
  store i8 0, ptr %_31.i.i312.sroa.66.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !45
  %_31.i.i312.sroa.67.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 82
  store i8 0, ptr %_31.i.i312.sroa.67.0.fresh.i.i314.sroa_idx.i, align 2, !noalias !45
  %_31.i.i312.sroa.68.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 83
  store i8 0, ptr %_31.i.i312.sroa.68.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !45
  %_31.i.i312.sroa.69.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 84
  store i8 0, ptr %_31.i.i312.sroa.69.0.fresh.i.i314.sroa_idx.i, align 4, !noalias !45
  %_31.i.i312.sroa.70.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 85
  store i8 0, ptr %_31.i.i312.sroa.70.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !45
  %_31.i.i312.sroa.71.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 86
  store i8 0, ptr %_31.i.i312.sroa.71.0.fresh.i.i314.sroa_idx.i, align 2, !noalias !45
  %_31.i.i312.sroa.72.0.fresh.i.i314.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i314.i, i64 87
  store i8 0, ptr %_31.i.i312.sroa.72.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !45
  %122 = icmp eq i8 %proto.i.i261.i, 6
  %123 = icmp eq i16 %dp.sroa.0.0.i.i, 443
  %or.cond1.i.i371.i = and i1 %122, %123
  br i1 %or.cond1.i.i371.i, label %bb5.i.i374.i, label %bb7.i.i372.i

bb2.i.i339.i:                                     ; preds = %bb11.i.i334.i
  %_28.i5.i.i341.i = load i32, ptr %ctx, align 4, !noalias !47, !noundef !12
  %_22.i6.i.i342.i = zext i32 %_28.i5.i.i341.i to i64
  %_21.i7.i.i343.i = inttoptr i64 %_22.i6.i.i342.i to ptr
  %_30.i8.i.i344.i = load i32, ptr %0, align 4, !noalias !47, !noundef !12
  %_24.i9.i.i345.i = zext i32 %_30.i8.i.i344.i to i64
  %_23.i10.i.i346.i = inttoptr i64 %_24.i9.i.i345.i to ptr
  %_25.i11.i.i347.i = getelementptr inbounds nuw i8, ptr %_21.i7.i.i343.i, i64 %payload_off.sroa.0.0.i331.i
  %_27.i12.i.i348.i = getelementptr inbounds nuw i8, ptr %_25.i11.i.i347.i, i64 1
  %_26.i13.i.i349.i = icmp samesign ugt ptr %_27.i12.i.i348.i, %_23.i10.i.i346.i
  br i1 %_26.i13.i.i349.i, label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i336.i, label %bb10.i14.i.i350.i

bb10.i14.i.i350.i:                                ; preds = %bb2.i.i339.i
  %_6.i15.i.i351.i = load i8, ptr %_25.i11.i.i347.i, align 1, !noalias !47, !noundef !12
  %124 = icmp ne i8 %_6.i15.i.i351.i, 22
  %_39.i17.i.i354.i = getelementptr i8, ptr %_25.i11.i.i347.i, i64 21
  %_38.i18.i.i355.i = icmp samesign ugt ptr %_39.i17.i.i354.i, %_23.i10.i.i346.i
  %or.cond766.i = or i1 %_38.i18.i.i355.i, %124
  br i1 %or.cond766.i, label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i336.i, label %bb12.i19.i.i356.i

bb12.i19.i.i356.i:                                ; preds = %bb10.i14.i.i350.i
  %_37.i20.i.i357.i = getelementptr i8, ptr %_25.i11.i.i347.i, i64 5
  %_13.i21.i.i358.i = getelementptr inbounds nuw i8, ptr %_0.i4, i64 24
  call void @llvm.memcpy.p0.p0.i64(ptr noundef nonnull align 1 dereferenceable(16) %_13.i21.i.i358.i, ptr noundef nonnull align 1 dereferenceable(16) %_37.i20.i.i357.i, i64 16, i1 false), !noalias !47
  %125 = getelementptr inbounds nuw i8, ptr %_0.i4, i64 25
  %126 = getelementptr inbounds nuw i8, ptr %_0.i4, i64 26
  %127 = getelementptr inbounds nuw i8, ptr %_0.i4, i64 27
  %128 = getelementptr inbounds nuw i8, ptr %_0.i4, i64 28
  %129 = getelementptr inbounds nuw i8, ptr %_0.i4, i64 29
  %130 = getelementptr inbounds nuw i8, ptr %_0.i4, i64 30
  %131 = getelementptr inbounds nuw i8, ptr %_0.i4, i64 31
  %132 = getelementptr inbounds nuw i8, ptr %_0.i4, i64 32
  %133 = getelementptr inbounds nuw i8, ptr %_0.i4, i64 33
  %134 = getelementptr inbounds nuw i8, ptr %_0.i4, i64 34
  %135 = getelementptr inbounds nuw i8, ptr %_0.i4, i64 35
  %136 = getelementptr inbounds nuw i8, ptr %_0.i4, i64 36
  %137 = getelementptr inbounds nuw i8, ptr %_0.i4, i64 37
  %138 = getelementptr inbounds nuw i8, ptr %_0.i4, i64 38
  %139 = getelementptr inbounds nuw i8, ptr %_0.i4, i64 39
  %140 = load <16 x i8>, ptr %_13.i21.i.i358.i, align 8, !noalias !47
  %141 = add <16 x i8> %140, splat (i8 -32)
  %142 = icmp ult <16 x i8> %141, splat (i8 95)
  %143 = select <16 x i1> %142, <16 x i8> %140, <16 x i8> zeroinitializer
  %144 = extractelement <16 x i8> %143, i64 0
  store i8 %144, ptr %_13.i21.i.i358.i, align 8, !noalias !47
  %145 = extractelement <16 x i8> %143, i64 1
  store i8 %145, ptr %125, align 1, !noalias !47
  %146 = extractelement <16 x i8> %143, i64 2
  store i8 %146, ptr %126, align 2, !noalias !47
  %147 = extractelement <16 x i8> %143, i64 3
  store i8 %147, ptr %127, align 1, !noalias !47
  %148 = extractelement <16 x i8> %143, i64 4
  store i8 %148, ptr %128, align 4, !noalias !47
  %149 = extractelement <16 x i8> %143, i64 5
  store i8 %149, ptr %129, align 1, !noalias !47
  %150 = extractelement <16 x i8> %143, i64 6
  store i8 %150, ptr %130, align 2, !noalias !47
  %151 = extractelement <16 x i8> %143, i64 7
  store i8 %151, ptr %131, align 1, !noalias !47
  %152 = extractelement <16 x i8> %143, i64 8
  store i8 %152, ptr %132, align 8, !noalias !47
  %153 = extractelement <16 x i8> %143, i64 9
  store i8 %153, ptr %133, align 1, !noalias !47
  %154 = extractelement <16 x i8> %143, i64 10
  store i8 %154, ptr %134, align 2, !noalias !47
  %155 = extractelement <16 x i8> %143, i64 11
  store i8 %155, ptr %135, align 1, !noalias !47
  %156 = extractelement <16 x i8> %143, i64 12
  store i8 %156, ptr %136, align 4, !noalias !47
  %157 = extractelement <16 x i8> %143, i64 13
  store i8 %157, ptr %137, align 1, !noalias !47
  %158 = extractelement <16 x i8> %143, i64 14
  store i8 %158, ptr %138, align 2, !noalias !47
  %159 = extractelement <16 x i8> %143, i64 15
  store i8 %159, ptr %139, align 1, !noalias !47
  br label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i336.i

bb7.i.i372.i:                                     ; preds = %bb12.i.i.i391.i, %bb10.i.i.i385.i, %bb5.i.i374.i, %bb10.i.i366.i
  %_0.i5 = call noundef i64 inttoptr (i64 2 to ptr)(ptr noundef nonnull @FLOW_METRICS, ptr noundef nonnull readonly align 4 dereferenceable(16) %key.i315.i, ptr noundef nonnull %fresh.i.i314.i, i64 noundef 0) #5
  call void @llvm.lifetime.end.p0(ptr nonnull %fresh.i.i314.i), !noalias !45
  br label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i336.i

bb5.i.i374.i:                                     ; preds = %bb10.i.i366.i
  %_28.i.i.i376.i = load i32, ptr %ctx, align 4, !noalias !50, !noundef !12
  %_22.i.i.i377.i = zext i32 %_28.i.i.i376.i to i64
  %_21.i.i.i378.i = inttoptr i64 %_22.i.i.i377.i to ptr
  %_30.i.i.i379.i = load i32, ptr %0, align 4, !noalias !50, !noundef !12
  %_24.i.i.i380.i = zext i32 %_30.i.i.i379.i to i64
  %_23.i.i.i381.i = inttoptr i64 %_24.i.i.i380.i to ptr
  %_25.i.i.i382.i = getelementptr inbounds nuw i8, ptr %_21.i.i.i378.i, i64 %payload_off.sroa.0.0.i331.i
  %_27.i.i.i383.i = getelementptr inbounds nuw i8, ptr %_25.i.i.i382.i, i64 1
  %_26.i.i.i384.i = icmp samesign ugt ptr %_27.i.i.i383.i, %_23.i.i.i381.i
  br i1 %_26.i.i.i384.i, label %bb7.i.i372.i, label %bb10.i.i.i385.i

bb10.i.i.i385.i:                                  ; preds = %bb5.i.i374.i
  %_6.i.i.i386.i = load i8, ptr %_25.i.i.i382.i, align 1, !noalias !50, !noundef !12
  %160 = icmp ne i8 %_6.i.i.i386.i, 22
  %_39.i.i.i389.i = getelementptr i8, ptr %_25.i.i.i382.i, i64 21
  %_38.i.i.i390.i = icmp samesign ugt ptr %_39.i.i.i389.i, %_23.i.i.i381.i
  %or.cond767.i = or i1 %_38.i.i.i390.i, %160
  br i1 %or.cond767.i, label %bb7.i.i372.i, label %bb12.i.i.i391.i

bb12.i.i.i391.i:                                  ; preds = %bb10.i.i.i385.i
  %_37.i.i.i392.i = getelementptr i8, ptr %_25.i.i.i382.i, i64 5
  call void @llvm.memcpy.p0.p0.i64(ptr noundef nonnull align 8 dereferenceable(16) %_31.i.i312.sroa.9.0.fresh.i.i314.sroa_idx.i, ptr noundef nonnull align 1 dereferenceable(16) %_37.i.i.i392.i, i64 16, i1 false), !noalias !50
  %161 = load <16 x i8>, ptr %_31.i.i312.sroa.9.0.fresh.i.i314.sroa_idx.i, align 8, !noalias !53
  %162 = add <16 x i8> %161, splat (i8 -32)
  %163 = icmp ult <16 x i8> %162, splat (i8 95)
  %164 = select <16 x i1> %163, <16 x i8> %161, <16 x i8> zeroinitializer
  %165 = extractelement <16 x i8> %164, i64 0
  store i8 %165, ptr %_31.i.i312.sroa.9.0.fresh.i.i314.sroa_idx.i, align 8, !noalias !53
  %166 = extractelement <16 x i8> %164, i64 1
  store i8 %166, ptr %_31.i.i312.sroa.10.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !53
  %167 = extractelement <16 x i8> %164, i64 2
  store i8 %167, ptr %_31.i.i312.sroa.11.0.fresh.i.i314.sroa_idx.i, align 2, !noalias !53
  %168 = extractelement <16 x i8> %164, i64 3
  store i8 %168, ptr %_31.i.i312.sroa.12.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !53
  %169 = extractelement <16 x i8> %164, i64 4
  store i8 %169, ptr %_31.i.i312.sroa.13.0.fresh.i.i314.sroa_idx.i, align 4, !noalias !53
  %170 = extractelement <16 x i8> %164, i64 5
  store i8 %170, ptr %_31.i.i312.sroa.14.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !53
  %171 = extractelement <16 x i8> %164, i64 6
  store i8 %171, ptr %_31.i.i312.sroa.15.0.fresh.i.i314.sroa_idx.i, align 2, !noalias !53
  %172 = extractelement <16 x i8> %164, i64 7
  store i8 %172, ptr %_31.i.i312.sroa.16.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !53
  %173 = extractelement <16 x i8> %164, i64 8
  store i8 %173, ptr %_31.i.i312.sroa.17.0.fresh.i.i314.sroa_idx.i, align 8, !noalias !53
  %174 = extractelement <16 x i8> %164, i64 9
  store i8 %174, ptr %_31.i.i312.sroa.18.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !53
  %175 = extractelement <16 x i8> %164, i64 10
  store i8 %175, ptr %_31.i.i312.sroa.19.0.fresh.i.i314.sroa_idx.i, align 2, !noalias !53
  %176 = extractelement <16 x i8> %164, i64 11
  store i8 %176, ptr %_31.i.i312.sroa.20.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !53
  %177 = extractelement <16 x i8> %164, i64 12
  store i8 %177, ptr %_31.i.i312.sroa.21.0.fresh.i.i314.sroa_idx.i, align 4, !noalias !53
  %178 = extractelement <16 x i8> %164, i64 13
  store i8 %178, ptr %_31.i.i312.sroa.22.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !53
  %179 = extractelement <16 x i8> %164, i64 14
  store i8 %179, ptr %_31.i.i312.sroa.23.0.fresh.i.i314.sroa_idx.i, align 2, !noalias !53
  %180 = extractelement <16 x i8> %164, i64 15
  store i8 %180, ptr %_31.i.i312.sroa.24.0.fresh.i.i314.sroa_idx.i, align 1, !noalias !53
  br label %bb7.i.i372.i

_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i336.i: ; preds = %bb7.i.i372.i, %bb12.i19.i.i356.i, %bb10.i14.i.i350.i, %bb2.i.i339.i, %bb11.i.i334.i
  call void @llvm.lifetime.end.p0(ptr nonnull %key.i315.i), !noalias !39
  br label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv410parse_ipv4.exit.i

bb13.i327.i:                                      ; preds = %bb5.i316.i
  %_23.i328.i = load i16, ptr %_48.i324.i, align 2, !noalias !39, !noundef !12
  %181 = tail call i16 @llvm.bswap.i16(i16 %_23.i328.i)
  %182 = getelementptr inbounds nuw i8, ptr %_48.i324.i, i64 2
  %_25.i329.i = load i16, ptr %182, align 2, !noalias !39, !noundef !12
  %183 = tail call i16 @llvm.bswap.i16(i16 %_25.i329.i)
  br label %bb6.i.i

bb8.i.i197.i:                                     ; preds = %bb2.i6.i186.i
  %_87.i.i198.i = getelementptr inbounds nuw i8, ptr %_49.i.i194.i, i64 8
  %_0.i6 = tail call noundef ptr inttoptr (i64 1 to ptr)(ptr noundef nonnull @BLOCKLIST_V6, ptr noundef nonnull %_87.i.i198.i) #5, !noalias !36
  %_88.i.i200.i = icmp eq ptr %_0.i6, null
  br i1 %_88.i.i200.i, label %bb15.i7.i206.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv410parse_ipv4.exit.i

bb15.i7.i206.i:                                   ; preds = %bb8.i.i197.i
  %184 = getelementptr inbounds nuw i8, ptr %_49.i.i194.i, i64 6
  %proto1.i.i207.i = load i8, ptr %184, align 2, !noalias !36, !noundef !12
  %xoff2.i.i208.i = add nuw nsw i64 %xport_off.i.i, 70
  %_92.i.i210.i = load i32, ptr %0, align 4, !noalias !36, !noundef !12
  %_30.i.i211.i = zext i32 %_92.i.i210.i to i64
  %_94.i.i212.i = load i32, ptr %ctx, align 4, !noalias !36, !noundef !12
  %_31.i8.i213.i = zext i32 %_94.i.i212.i to i64
  %_29.i.i214.i = sub nsw i64 %_30.i.i211.i, %_31.i8.i213.i
  %185 = getelementptr inbounds nuw i8, ptr %_49.i.i194.i, i64 20
  %_34.i9.i215.i = load i8, ptr %185, align 4, !noalias !36, !noundef !12
  %186 = getelementptr inbounds nuw i8, ptr %_49.i.i194.i, i64 21
  %_35.i.i216.i = load i8, ptr %186, align 1, !noalias !36, !noundef !12
  %187 = getelementptr inbounds nuw i8, ptr %_49.i.i194.i, i64 22
  %_36.i.i217.i = load i8, ptr %187, align 2, !noalias !36, !noundef !12
  %188 = getelementptr inbounds nuw i8, ptr %_49.i.i194.i, i64 23
  %_37.i.i218.i = load i8, ptr %188, align 1, !noalias !36, !noundef !12
  %_33.sroa.6.0.insert.ext.i.i219.i = zext i8 %_37.i.i218.i to i32
  %_33.sroa.6.0.insert.shift.i.i220.i = shl nuw i32 %_33.sroa.6.0.insert.ext.i.i219.i, 24
  %_33.sroa.5.0.insert.ext.i.i221.i = zext i8 %_36.i.i217.i to i32
  %_33.sroa.5.0.insert.shift.i.i222.i = shl nuw nsw i32 %_33.sroa.5.0.insert.ext.i.i221.i, 16
  %_33.sroa.4.0.insert.ext.i.i224.i = zext i8 %_35.i.i216.i to i32
  %_33.sroa.4.0.insert.shift.i.i225.i = shl nuw nsw i32 %_33.sroa.4.0.insert.ext.i.i224.i, 8
  %_33.sroa.0.0.insert.ext.i.i227.i = zext i8 %_34.i9.i215.i to i32
  %_33.sroa.5.0.insert.insert.i.i223.i = or disjoint i32 %_33.sroa.4.0.insert.shift.i.i225.i, %_33.sroa.0.0.insert.ext.i.i227.i
  %_33.sroa.4.0.insert.insert.i.i226.i = or disjoint i32 %_33.sroa.5.0.insert.insert.i.i223.i, %_33.sroa.5.0.insert.shift.i.i222.i
  %_33.sroa.0.0.insert.insert.i.i228.i = or disjoint i32 %_33.sroa.4.0.insert.insert.i.i226.i, %_33.sroa.6.0.insert.shift.i.i220.i
  %src_lo.i.i229.i = tail call i32 @llvm.bswap.i32(i32 %_33.sroa.0.0.insert.insert.i.i228.i)
  %189 = getelementptr inbounds nuw i8, ptr %_49.i.i194.i, i64 36
  %_40.i.i230.i = load i8, ptr %189, align 4, !noalias !36, !noundef !12
  %190 = getelementptr inbounds nuw i8, ptr %_49.i.i194.i, i64 37
  %_41.i.i231.i = load i8, ptr %190, align 1, !noalias !36, !noundef !12
  %191 = getelementptr inbounds nuw i8, ptr %_49.i.i194.i, i64 38
  %_42.i.i232.i = load i8, ptr %191, align 2, !noalias !36, !noundef !12
  %192 = getelementptr inbounds nuw i8, ptr %_49.i.i194.i, i64 39
  %_43.i.i233.i = load i8, ptr %192, align 1, !noalias !36, !noundef !12
  %_39.sroa.6.0.insert.ext.i.i234.i = zext i8 %_43.i.i233.i to i32
  %_39.sroa.6.0.insert.shift.i.i235.i = shl nuw i32 %_39.sroa.6.0.insert.ext.i.i234.i, 24
  %_39.sroa.5.0.insert.ext.i.i236.i = zext i8 %_42.i.i232.i to i32
  %_39.sroa.5.0.insert.shift.i.i237.i = shl nuw nsw i32 %_39.sroa.5.0.insert.ext.i.i236.i, 16
  %_39.sroa.4.0.insert.ext.i.i239.i = zext i8 %_41.i.i231.i to i32
  %_39.sroa.4.0.insert.shift.i.i240.i = shl nuw nsw i32 %_39.sroa.4.0.insert.ext.i.i239.i, 8
  %_39.sroa.0.0.insert.ext.i.i242.i = zext i8 %_40.i.i230.i to i32
  %_39.sroa.5.0.insert.insert.i.i238.i = or disjoint i32 %_39.sroa.4.0.insert.shift.i.i240.i, %_39.sroa.0.0.insert.ext.i.i242.i
  %_39.sroa.4.0.insert.insert.i.i241.i = or disjoint i32 %_39.sroa.5.0.insert.insert.i.i238.i, %_39.sroa.5.0.insert.shift.i.i237.i
  %_39.sroa.0.0.insert.insert.i.i243.i = or disjoint i32 %_39.sroa.4.0.insert.insert.i.i241.i, %_39.sroa.6.0.insert.shift.i.i235.i
  %dst_lo.i.i244.i = tail call i32 @llvm.bswap.i32(i32 %_39.sroa.0.0.insert.insert.i.i243.i)
  switch i8 %proto1.i.i207.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv410parse_ipv4.exit.i [
    i8 6, label %bb4.i512.i
    i8 17, label %bb5.i420.i
  ]

bb4.i512.i:                                       ; preds = %bb15.i7.i206.i
  %_31.i516.i = inttoptr i64 %_31.i8.i213.i to ptr
  %_33.i519.i = inttoptr i64 %_30.i.i211.i to ptr
  %_36.i520.i = getelementptr inbounds nuw i8, ptr %_31.i516.i, i64 %xoff2.i.i208.i
  %_38.i521.i = getelementptr inbounds nuw i8, ptr %_36.i520.i, i64 20
  %_37.i522.i = icmp samesign ugt ptr %_38.i521.i, %_33.i519.i
  br i1 %_37.i522.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv410parse_ipv4.exit.i, label %bb11.i523.i

bb5.i420.i:                                       ; preds = %bb15.i7.i206.i
  %_43.i424.i = inttoptr i64 %_31.i8.i213.i to ptr
  %_45.i427.i = inttoptr i64 %_30.i.i211.i to ptr
  %_48.i428.i = getelementptr inbounds nuw i8, ptr %_43.i424.i, i64 %xoff2.i.i208.i
  %_50.i429.i = getelementptr inbounds nuw i8, ptr %_48.i428.i, i64 8
  %_49.i430.i = icmp samesign ugt ptr %_50.i429.i, %_45.i427.i
  br i1 %_49.i430.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv410parse_ipv4.exit.i, label %bb13.i431.i

bb11.i523.i:                                      ; preds = %bb4.i512.i
  %193 = getelementptr inbounds nuw i8, ptr %_36.i520.i, i64 12
  %_14.i524.i = load i8, ptr %193, align 4, !noalias !54, !noundef !12
  %194 = lshr i8 %_14.i524.i, 2
  %195 = and i8 %194, 60
  %thlen.i525.i = zext nneg i8 %195 to i64
  %_15.i526.i = load i16, ptr %_36.i520.i, align 4, !noalias !54, !noundef !12
  %196 = tail call i16 @llvm.bswap.i16(i16 %_15.i526.i)
  %197 = getelementptr inbounds nuw i8, ptr %_36.i520.i, i64 2
  %_16.i527.i = load i16, ptr %197, align 2, !noalias !54, !noundef !12
  %198 = tail call i16 @llvm.bswap.i16(i16 %_16.i527.i)
  %199 = getelementptr inbounds nuw i8, ptr %_36.i520.i, i64 13
  %200 = load i8, ptr %199, align 1, !noalias !54, !noundef !12
  br label %bb6.i434.i

bb6.i434.i:                                       ; preds = %bb13.i431.i, %bb11.i523.i
  %flags.sroa.0.0.i435.i = phi i8 [ %200, %bb11.i523.i ], [ 0, %bb13.i431.i ]
  %sp.sroa.0.0.i436.i = phi i16 [ %196, %bb11.i523.i ], [ %276, %bb13.i431.i ]
  %dp.sroa.0.0.i437.i = phi i16 [ %198, %bb11.i523.i ], [ %278, %bb13.i431.i ]
  %thlen.pn.i438.i = phi i64 [ %thlen.i525.i, %bb11.i523.i ], [ 8, %bb13.i431.i ]
  %payload_off.sroa.0.0.i439.i = add nuw nsw i64 %thlen.pn.i438.i, %xoff2.i.i208.i
  call void @llvm.lifetime.start.p0(ptr nonnull %key.i419.i), !noalias !54
  store i32 %src_lo.i.i229.i, ptr %key.i419.i, align 4, !noalias !54
  %201 = getelementptr inbounds nuw i8, ptr %key.i419.i, i64 4
  store i32 %dst_lo.i.i244.i, ptr %201, align 4, !noalias !54
  %202 = getelementptr inbounds nuw i8, ptr %key.i419.i, i64 8
  store i16 %sp.sroa.0.0.i436.i, ptr %202, align 4, !noalias !54
  %203 = getelementptr inbounds nuw i8, ptr %key.i419.i, i64 10
  store i16 %dp.sroa.0.0.i437.i, ptr %203, align 2, !noalias !54
  %204 = getelementptr inbounds nuw i8, ptr %key.i419.i, i64 12
  store i8 %proto1.i.i207.i, ptr %204, align 4, !noalias !54
  %205 = getelementptr inbounds nuw i8, ptr %key.i419.i, i64 13
  store i8 0, ptr %205, align 1, !noalias !54
  %_28.sroa.4.0..sroa_idx.i440.i = getelementptr inbounds nuw i8, ptr %key.i419.i, i64 14
  store i8 0, ptr %_28.sroa.4.0..sroa_idx.i440.i, align 2, !noalias !54
  %_28.sroa.5.0..sroa_idx.i441.i = getelementptr inbounds nuw i8, ptr %key.i419.i, i64 15
  store i8 0, ptr %_28.sroa.5.0..sroa_idx.i441.i, align 1, !noalias !54
  %_0.i7 = call noundef ptr inttoptr (i64 1 to ptr)(ptr noundef nonnull @FLOW_METRICS, ptr noundef nonnull readonly align 4 dereferenceable(16) %key.i419.i) #5, !noalias !57
  %_20.i.i443.i = icmp eq ptr %_0.i7, null
  br i1 %_20.i.i443.i, label %bb10.i.i476.i, label %bb11.i.i444.i

bb11.i.i444.i:                                    ; preds = %bb6.i434.i
  %206 = getelementptr inbounds nuw i8, ptr %_0.i7, i64 8
  %207 = load <2 x i64>, ptr %_0.i7, align 8, !noalias !57
  %208 = insertelement <2 x i64> <i64 poison, i64 1>, i64 %_29.i.i214.i, i64 0
  %209 = add <2 x i64> %207, %208
  %210 = extractelement <2 x i64> %209, i64 0
  store i64 %210, ptr %_0.i7, align 8, !noalias !57
  %211 = extractelement <2 x i64> %209, i64 1
  store i64 %211, ptr %206, align 8, !noalias !57
  %212 = getelementptr inbounds nuw i8, ptr %_0.i7, i64 16
  %213 = load i8, ptr %212, align 8, !noalias !57, !noundef !12
  %214 = or i8 %213, %flags.sroa.0.0.i435.i
  store i8 %214, ptr %212, align 8, !noalias !57
  %215 = icmp eq i8 %proto1.i.i207.i, 6
  %216 = icmp eq i16 %dp.sroa.0.0.i437.i, 443
  %or.cond.i.i445.i = and i1 %215, %216
  br i1 %or.cond.i.i445.i, label %bb2.i.i449.i, label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i446.i

bb10.i.i476.i:                                    ; preds = %bb6.i434.i
  call void @llvm.lifetime.start.p0(ptr nonnull %fresh.i.i418.i), !noalias !60
  store i64 %_29.i.i214.i, ptr %fresh.i.i418.i, align 8, !noalias !60
  %_31.i.i416.sroa.4.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 8
  store i64 1, ptr %_31.i.i416.sroa.4.0.fresh.i.i418.sroa_idx.i, align 8, !noalias !60
  %_31.i.i416.sroa.5.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 16
  store i8 %flags.sroa.0.0.i435.i, ptr %_31.i.i416.sroa.5.0.fresh.i.i418.sroa_idx.i, align 8, !noalias !60
  %_31.i.i416.sroa.6.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 17
  store i8 0, ptr %_31.i.i416.sroa.6.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !60
  %_31.i.i416.sroa.7.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 18
  store i16 0, ptr %_31.i.i416.sroa.7.0.fresh.i.i418.sroa_idx.i, align 2, !noalias !60
  %_31.i.i416.sroa.8.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 20
  store i32 0, ptr %_31.i.i416.sroa.8.0.fresh.i.i418.sroa_idx.i, align 4, !noalias !60
  %_31.i.i416.sroa.9.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 24
  store i8 0, ptr %_31.i.i416.sroa.9.0.fresh.i.i418.sroa_idx.i, align 8, !noalias !60
  %_31.i.i416.sroa.10.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 25
  store i8 0, ptr %_31.i.i416.sroa.10.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !60
  %_31.i.i416.sroa.11.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 26
  store i8 0, ptr %_31.i.i416.sroa.11.0.fresh.i.i418.sroa_idx.i, align 2, !noalias !60
  %_31.i.i416.sroa.12.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 27
  store i8 0, ptr %_31.i.i416.sroa.12.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !60
  %_31.i.i416.sroa.13.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 28
  store i8 0, ptr %_31.i.i416.sroa.13.0.fresh.i.i418.sroa_idx.i, align 4, !noalias !60
  %_31.i.i416.sroa.14.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 29
  store i8 0, ptr %_31.i.i416.sroa.14.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !60
  %_31.i.i416.sroa.15.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 30
  store i8 0, ptr %_31.i.i416.sroa.15.0.fresh.i.i418.sroa_idx.i, align 2, !noalias !60
  %_31.i.i416.sroa.16.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 31
  store i8 0, ptr %_31.i.i416.sroa.16.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !60
  %_31.i.i416.sroa.17.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 32
  store i8 0, ptr %_31.i.i416.sroa.17.0.fresh.i.i418.sroa_idx.i, align 8, !noalias !60
  %_31.i.i416.sroa.18.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 33
  store i8 0, ptr %_31.i.i416.sroa.18.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !60
  %_31.i.i416.sroa.19.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 34
  store i8 0, ptr %_31.i.i416.sroa.19.0.fresh.i.i418.sroa_idx.i, align 2, !noalias !60
  %_31.i.i416.sroa.20.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 35
  store i8 0, ptr %_31.i.i416.sroa.20.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !60
  %_31.i.i416.sroa.21.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 36
  store i8 0, ptr %_31.i.i416.sroa.21.0.fresh.i.i418.sroa_idx.i, align 4, !noalias !60
  %_31.i.i416.sroa.22.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 37
  store i8 0, ptr %_31.i.i416.sroa.22.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !60
  %_31.i.i416.sroa.23.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 38
  store i8 0, ptr %_31.i.i416.sroa.23.0.fresh.i.i418.sroa_idx.i, align 2, !noalias !60
  %_31.i.i416.sroa.24.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 39
  store i8 0, ptr %_31.i.i416.sroa.24.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !60
  %_31.i.i416.sroa.25.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 40
  store i8 0, ptr %_31.i.i416.sroa.25.0.fresh.i.i418.sroa_idx.i, align 8, !noalias !60
  %_31.i.i416.sroa.26.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 41
  store i8 0, ptr %_31.i.i416.sroa.26.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !60
  %_31.i.i416.sroa.27.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 42
  store i8 0, ptr %_31.i.i416.sroa.27.0.fresh.i.i418.sroa_idx.i, align 2, !noalias !60
  %_31.i.i416.sroa.28.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 43
  store i8 0, ptr %_31.i.i416.sroa.28.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !60
  %_31.i.i416.sroa.29.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 44
  store i8 0, ptr %_31.i.i416.sroa.29.0.fresh.i.i418.sroa_idx.i, align 4, !noalias !60
  %_31.i.i416.sroa.30.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 45
  store i8 0, ptr %_31.i.i416.sroa.30.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !60
  %_31.i.i416.sroa.31.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 46
  store i8 0, ptr %_31.i.i416.sroa.31.0.fresh.i.i418.sroa_idx.i, align 2, !noalias !60
  %_31.i.i416.sroa.32.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 47
  store i8 0, ptr %_31.i.i416.sroa.32.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !60
  %_31.i.i416.sroa.33.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 48
  store i8 0, ptr %_31.i.i416.sroa.33.0.fresh.i.i418.sroa_idx.i, align 8, !noalias !60
  %_31.i.i416.sroa.34.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 49
  store i8 0, ptr %_31.i.i416.sroa.34.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !60
  %_31.i.i416.sroa.35.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 50
  store i8 0, ptr %_31.i.i416.sroa.35.0.fresh.i.i418.sroa_idx.i, align 2, !noalias !60
  %_31.i.i416.sroa.36.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 51
  store i8 0, ptr %_31.i.i416.sroa.36.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !60
  %_31.i.i416.sroa.37.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 52
  store i8 0, ptr %_31.i.i416.sroa.37.0.fresh.i.i418.sroa_idx.i, align 4, !noalias !60
  %_31.i.i416.sroa.38.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 53
  store i8 0, ptr %_31.i.i416.sroa.38.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !60
  %_31.i.i416.sroa.39.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 54
  store i8 0, ptr %_31.i.i416.sroa.39.0.fresh.i.i418.sroa_idx.i, align 2, !noalias !60
  %_31.i.i416.sroa.40.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 55
  store i8 0, ptr %_31.i.i416.sroa.40.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !60
  %_31.i.i416.sroa.41.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 56
  store i8 0, ptr %_31.i.i416.sroa.41.0.fresh.i.i418.sroa_idx.i, align 8, !noalias !60
  %_31.i.i416.sroa.42.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 57
  store i8 0, ptr %_31.i.i416.sroa.42.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !60
  %_31.i.i416.sroa.43.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 58
  store i8 0, ptr %_31.i.i416.sroa.43.0.fresh.i.i418.sroa_idx.i, align 2, !noalias !60
  %_31.i.i416.sroa.44.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 59
  store i8 0, ptr %_31.i.i416.sroa.44.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !60
  %_31.i.i416.sroa.45.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 60
  store i8 0, ptr %_31.i.i416.sroa.45.0.fresh.i.i418.sroa_idx.i, align 4, !noalias !60
  %_31.i.i416.sroa.46.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 61
  store i8 0, ptr %_31.i.i416.sroa.46.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !60
  %_31.i.i416.sroa.47.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 62
  store i8 0, ptr %_31.i.i416.sroa.47.0.fresh.i.i418.sroa_idx.i, align 2, !noalias !60
  %_31.i.i416.sroa.48.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 63
  store i8 0, ptr %_31.i.i416.sroa.48.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !60
  %_31.i.i416.sroa.49.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 64
  store i8 0, ptr %_31.i.i416.sroa.49.0.fresh.i.i418.sroa_idx.i, align 8, !noalias !60
  %_31.i.i416.sroa.50.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 65
  store i8 0, ptr %_31.i.i416.sroa.50.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !60
  %_31.i.i416.sroa.51.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 66
  store i8 0, ptr %_31.i.i416.sroa.51.0.fresh.i.i418.sroa_idx.i, align 2, !noalias !60
  %_31.i.i416.sroa.52.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 67
  store i8 0, ptr %_31.i.i416.sroa.52.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !60
  %_31.i.i416.sroa.53.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 68
  store i8 0, ptr %_31.i.i416.sroa.53.0.fresh.i.i418.sroa_idx.i, align 4, !noalias !60
  %_31.i.i416.sroa.54.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 69
  store i8 0, ptr %_31.i.i416.sroa.54.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !60
  %_31.i.i416.sroa.55.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 70
  store i8 0, ptr %_31.i.i416.sroa.55.0.fresh.i.i418.sroa_idx.i, align 2, !noalias !60
  %_31.i.i416.sroa.56.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 71
  store i8 0, ptr %_31.i.i416.sroa.56.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !60
  %_31.i.i416.sroa.57.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 72
  store i8 0, ptr %_31.i.i416.sroa.57.0.fresh.i.i418.sroa_idx.i, align 8, !noalias !60
  %_31.i.i416.sroa.58.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 73
  store i8 0, ptr %_31.i.i416.sroa.58.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !60
  %_31.i.i416.sroa.59.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 74
  store i8 0, ptr %_31.i.i416.sroa.59.0.fresh.i.i418.sroa_idx.i, align 2, !noalias !60
  %_31.i.i416.sroa.60.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 75
  store i8 0, ptr %_31.i.i416.sroa.60.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !60
  %_31.i.i416.sroa.61.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 76
  store i8 0, ptr %_31.i.i416.sroa.61.0.fresh.i.i418.sroa_idx.i, align 4, !noalias !60
  %_31.i.i416.sroa.62.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 77
  store i8 0, ptr %_31.i.i416.sroa.62.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !60
  %_31.i.i416.sroa.63.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 78
  store i8 0, ptr %_31.i.i416.sroa.63.0.fresh.i.i418.sroa_idx.i, align 2, !noalias !60
  %_31.i.i416.sroa.64.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 79
  store i8 0, ptr %_31.i.i416.sroa.64.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !60
  %_31.i.i416.sroa.65.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 80
  store i8 0, ptr %_31.i.i416.sroa.65.0.fresh.i.i418.sroa_idx.i, align 8, !noalias !60
  %_31.i.i416.sroa.66.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 81
  store i8 0, ptr %_31.i.i416.sroa.66.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !60
  %_31.i.i416.sroa.67.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 82
  store i8 0, ptr %_31.i.i416.sroa.67.0.fresh.i.i418.sroa_idx.i, align 2, !noalias !60
  %_31.i.i416.sroa.68.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 83
  store i8 0, ptr %_31.i.i416.sroa.68.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !60
  %_31.i.i416.sroa.69.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 84
  store i8 0, ptr %_31.i.i416.sroa.69.0.fresh.i.i418.sroa_idx.i, align 4, !noalias !60
  %_31.i.i416.sroa.70.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 85
  store i8 0, ptr %_31.i.i416.sroa.70.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !60
  %_31.i.i416.sroa.71.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 86
  store i8 0, ptr %_31.i.i416.sroa.71.0.fresh.i.i418.sroa_idx.i, align 2, !noalias !60
  %_31.i.i416.sroa.72.0.fresh.i.i418.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i418.i, i64 87
  store i8 0, ptr %_31.i.i416.sroa.72.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !60
  %217 = icmp eq i8 %proto1.i.i207.i, 6
  %218 = icmp eq i16 %dp.sroa.0.0.i437.i, 443
  %or.cond1.i.i481.i = and i1 %217, %218
  br i1 %or.cond1.i.i481.i, label %bb5.i.i484.i, label %bb7.i.i482.i

bb2.i.i449.i:                                     ; preds = %bb11.i.i444.i
  %_28.i5.i.i451.i = load i32, ptr %ctx, align 4, !noalias !62, !noundef !12
  %_22.i6.i.i452.i = zext i32 %_28.i5.i.i451.i to i64
  %_21.i7.i.i453.i = inttoptr i64 %_22.i6.i.i452.i to ptr
  %_30.i8.i.i454.i = load i32, ptr %0, align 4, !noalias !62, !noundef !12
  %_24.i9.i.i455.i = zext i32 %_30.i8.i.i454.i to i64
  %_23.i10.i.i456.i = inttoptr i64 %_24.i9.i.i455.i to ptr
  %_25.i11.i.i457.i = getelementptr inbounds nuw i8, ptr %_21.i7.i.i453.i, i64 %payload_off.sroa.0.0.i439.i
  %_27.i12.i.i458.i = getelementptr inbounds nuw i8, ptr %_25.i11.i.i457.i, i64 1
  %_26.i13.i.i459.i = icmp samesign ugt ptr %_27.i12.i.i458.i, %_23.i10.i.i456.i
  br i1 %_26.i13.i.i459.i, label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i446.i, label %bb10.i14.i.i460.i

bb10.i14.i.i460.i:                                ; preds = %bb2.i.i449.i
  %_6.i15.i.i461.i = load i8, ptr %_25.i11.i.i457.i, align 1, !noalias !62, !noundef !12
  %219 = icmp ne i8 %_6.i15.i.i461.i, 22
  %_39.i17.i.i464.i = getelementptr i8, ptr %_25.i11.i.i457.i, i64 21
  %_38.i18.i.i465.i = icmp samesign ugt ptr %_39.i17.i.i464.i, %_23.i10.i.i456.i
  %or.cond768.i = or i1 %_38.i18.i.i465.i, %219
  br i1 %or.cond768.i, label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i446.i, label %bb12.i19.i.i466.i

bb12.i19.i.i466.i:                                ; preds = %bb10.i14.i.i460.i
  %_37.i20.i.i467.i = getelementptr i8, ptr %_25.i11.i.i457.i, i64 5
  %_13.i21.i.i468.i = getelementptr inbounds nuw i8, ptr %_0.i7, i64 24
  call void @llvm.memcpy.p0.p0.i64(ptr noundef nonnull align 1 dereferenceable(16) %_13.i21.i.i468.i, ptr noundef nonnull align 1 dereferenceable(16) %_37.i20.i.i467.i, i64 16, i1 false), !noalias !62
  %220 = getelementptr inbounds nuw i8, ptr %_0.i7, i64 25
  %221 = getelementptr inbounds nuw i8, ptr %_0.i7, i64 26
  %222 = getelementptr inbounds nuw i8, ptr %_0.i7, i64 27
  %223 = getelementptr inbounds nuw i8, ptr %_0.i7, i64 28
  %224 = getelementptr inbounds nuw i8, ptr %_0.i7, i64 29
  %225 = getelementptr inbounds nuw i8, ptr %_0.i7, i64 30
  %226 = getelementptr inbounds nuw i8, ptr %_0.i7, i64 31
  %227 = getelementptr inbounds nuw i8, ptr %_0.i7, i64 32
  %228 = getelementptr inbounds nuw i8, ptr %_0.i7, i64 33
  %229 = getelementptr inbounds nuw i8, ptr %_0.i7, i64 34
  %230 = getelementptr inbounds nuw i8, ptr %_0.i7, i64 35
  %231 = getelementptr inbounds nuw i8, ptr %_0.i7, i64 36
  %232 = getelementptr inbounds nuw i8, ptr %_0.i7, i64 37
  %233 = getelementptr inbounds nuw i8, ptr %_0.i7, i64 38
  %234 = getelementptr inbounds nuw i8, ptr %_0.i7, i64 39
  %235 = load <16 x i8>, ptr %_13.i21.i.i468.i, align 8, !noalias !62
  %236 = add <16 x i8> %235, splat (i8 -32)
  %237 = icmp ult <16 x i8> %236, splat (i8 95)
  %238 = select <16 x i1> %237, <16 x i8> %235, <16 x i8> zeroinitializer
  %239 = extractelement <16 x i8> %238, i64 0
  store i8 %239, ptr %_13.i21.i.i468.i, align 8, !noalias !62
  %240 = extractelement <16 x i8> %238, i64 1
  store i8 %240, ptr %220, align 1, !noalias !62
  %241 = extractelement <16 x i8> %238, i64 2
  store i8 %241, ptr %221, align 2, !noalias !62
  %242 = extractelement <16 x i8> %238, i64 3
  store i8 %242, ptr %222, align 1, !noalias !62
  %243 = extractelement <16 x i8> %238, i64 4
  store i8 %243, ptr %223, align 4, !noalias !62
  %244 = extractelement <16 x i8> %238, i64 5
  store i8 %244, ptr %224, align 1, !noalias !62
  %245 = extractelement <16 x i8> %238, i64 6
  store i8 %245, ptr %225, align 2, !noalias !62
  %246 = extractelement <16 x i8> %238, i64 7
  store i8 %246, ptr %226, align 1, !noalias !62
  %247 = extractelement <16 x i8> %238, i64 8
  store i8 %247, ptr %227, align 8, !noalias !62
  %248 = extractelement <16 x i8> %238, i64 9
  store i8 %248, ptr %228, align 1, !noalias !62
  %249 = extractelement <16 x i8> %238, i64 10
  store i8 %249, ptr %229, align 2, !noalias !62
  %250 = extractelement <16 x i8> %238, i64 11
  store i8 %250, ptr %230, align 1, !noalias !62
  %251 = extractelement <16 x i8> %238, i64 12
  store i8 %251, ptr %231, align 4, !noalias !62
  %252 = extractelement <16 x i8> %238, i64 13
  store i8 %252, ptr %232, align 1, !noalias !62
  %253 = extractelement <16 x i8> %238, i64 14
  store i8 %253, ptr %233, align 2, !noalias !62
  %254 = extractelement <16 x i8> %238, i64 15
  store i8 %254, ptr %234, align 1, !noalias !62
  br label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i446.i

bb7.i.i482.i:                                     ; preds = %bb12.i.i.i501.i, %bb10.i.i.i495.i, %bb5.i.i484.i, %bb10.i.i476.i
  %_0.i8 = call noundef i64 inttoptr (i64 2 to ptr)(ptr noundef nonnull @FLOW_METRICS, ptr noundef nonnull readonly align 4 dereferenceable(16) %key.i419.i, ptr noundef nonnull %fresh.i.i418.i, i64 noundef 0) #5
  call void @llvm.lifetime.end.p0(ptr nonnull %fresh.i.i418.i), !noalias !60
  br label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i446.i

bb5.i.i484.i:                                     ; preds = %bb10.i.i476.i
  %_28.i.i.i486.i = load i32, ptr %ctx, align 4, !noalias !65, !noundef !12
  %_22.i.i.i487.i = zext i32 %_28.i.i.i486.i to i64
  %_21.i.i.i488.i = inttoptr i64 %_22.i.i.i487.i to ptr
  %_30.i.i.i489.i = load i32, ptr %0, align 4, !noalias !65, !noundef !12
  %_24.i.i.i490.i = zext i32 %_30.i.i.i489.i to i64
  %_23.i.i.i491.i = inttoptr i64 %_24.i.i.i490.i to ptr
  %_25.i.i.i492.i = getelementptr inbounds nuw i8, ptr %_21.i.i.i488.i, i64 %payload_off.sroa.0.0.i439.i
  %_27.i.i.i493.i = getelementptr inbounds nuw i8, ptr %_25.i.i.i492.i, i64 1
  %_26.i.i.i494.i = icmp samesign ugt ptr %_27.i.i.i493.i, %_23.i.i.i491.i
  br i1 %_26.i.i.i494.i, label %bb7.i.i482.i, label %bb10.i.i.i495.i

bb10.i.i.i495.i:                                  ; preds = %bb5.i.i484.i
  %_6.i.i.i496.i = load i8, ptr %_25.i.i.i492.i, align 1, !noalias !65, !noundef !12
  %255 = icmp ne i8 %_6.i.i.i496.i, 22
  %_39.i.i.i499.i = getelementptr i8, ptr %_25.i.i.i492.i, i64 21
  %_38.i.i.i500.i = icmp samesign ugt ptr %_39.i.i.i499.i, %_23.i.i.i491.i
  %or.cond769.i = or i1 %_38.i.i.i500.i, %255
  br i1 %or.cond769.i, label %bb7.i.i482.i, label %bb12.i.i.i501.i

bb12.i.i.i501.i:                                  ; preds = %bb10.i.i.i495.i
  %_37.i.i.i502.i = getelementptr i8, ptr %_25.i.i.i492.i, i64 5
  call void @llvm.memcpy.p0.p0.i64(ptr noundef nonnull align 8 dereferenceable(16) %_31.i.i416.sroa.9.0.fresh.i.i418.sroa_idx.i, ptr noundef nonnull align 1 dereferenceable(16) %_37.i.i.i502.i, i64 16, i1 false), !noalias !65
  %256 = load <16 x i8>, ptr %_31.i.i416.sroa.9.0.fresh.i.i418.sroa_idx.i, align 8, !noalias !68
  %257 = add <16 x i8> %256, splat (i8 -32)
  %258 = icmp ult <16 x i8> %257, splat (i8 95)
  %259 = select <16 x i1> %258, <16 x i8> %256, <16 x i8> zeroinitializer
  %260 = extractelement <16 x i8> %259, i64 0
  store i8 %260, ptr %_31.i.i416.sroa.9.0.fresh.i.i418.sroa_idx.i, align 8, !noalias !68
  %261 = extractelement <16 x i8> %259, i64 1
  store i8 %261, ptr %_31.i.i416.sroa.10.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !68
  %262 = extractelement <16 x i8> %259, i64 2
  store i8 %262, ptr %_31.i.i416.sroa.11.0.fresh.i.i418.sroa_idx.i, align 2, !noalias !68
  %263 = extractelement <16 x i8> %259, i64 3
  store i8 %263, ptr %_31.i.i416.sroa.12.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !68
  %264 = extractelement <16 x i8> %259, i64 4
  store i8 %264, ptr %_31.i.i416.sroa.13.0.fresh.i.i418.sroa_idx.i, align 4, !noalias !68
  %265 = extractelement <16 x i8> %259, i64 5
  store i8 %265, ptr %_31.i.i416.sroa.14.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !68
  %266 = extractelement <16 x i8> %259, i64 6
  store i8 %266, ptr %_31.i.i416.sroa.15.0.fresh.i.i418.sroa_idx.i, align 2, !noalias !68
  %267 = extractelement <16 x i8> %259, i64 7
  store i8 %267, ptr %_31.i.i416.sroa.16.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !68
  %268 = extractelement <16 x i8> %259, i64 8
  store i8 %268, ptr %_31.i.i416.sroa.17.0.fresh.i.i418.sroa_idx.i, align 8, !noalias !68
  %269 = extractelement <16 x i8> %259, i64 9
  store i8 %269, ptr %_31.i.i416.sroa.18.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !68
  %270 = extractelement <16 x i8> %259, i64 10
  store i8 %270, ptr %_31.i.i416.sroa.19.0.fresh.i.i418.sroa_idx.i, align 2, !noalias !68
  %271 = extractelement <16 x i8> %259, i64 11
  store i8 %271, ptr %_31.i.i416.sroa.20.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !68
  %272 = extractelement <16 x i8> %259, i64 12
  store i8 %272, ptr %_31.i.i416.sroa.21.0.fresh.i.i418.sroa_idx.i, align 4, !noalias !68
  %273 = extractelement <16 x i8> %259, i64 13
  store i8 %273, ptr %_31.i.i416.sroa.22.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !68
  %274 = extractelement <16 x i8> %259, i64 14
  store i8 %274, ptr %_31.i.i416.sroa.23.0.fresh.i.i418.sroa_idx.i, align 2, !noalias !68
  %275 = extractelement <16 x i8> %259, i64 15
  store i8 %275, ptr %_31.i.i416.sroa.24.0.fresh.i.i418.sroa_idx.i, align 1, !noalias !68
  br label %bb7.i.i482.i

_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i446.i: ; preds = %bb7.i.i482.i, %bb12.i19.i.i466.i, %bb10.i14.i.i460.i, %bb2.i.i449.i, %bb11.i.i444.i
  call void @llvm.lifetime.end.p0(ptr nonnull %key.i419.i), !noalias !54
  br label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv410parse_ipv4.exit.i

bb13.i431.i:                                      ; preds = %bb5.i420.i
  %_23.i432.i = load i16, ptr %_48.i428.i, align 2, !noalias !54, !noundef !12
  %276 = tail call i16 @llvm.bswap.i16(i16 %_23.i432.i)
  %277 = getelementptr inbounds nuw i8, ptr %_48.i428.i, i64 2
  %_25.i433.i = load i16, ptr %277, align 2, !noalias !54, !noundef !12
  %278 = tail call i16 @llvm.bswap.i16(i16 %_25.i433.i)
  br label %bb6.i434.i

bb4.i.i:                                          ; preds = %bb13.i.i
  %_62.i.i = inttoptr i64 %_21.i.i to ptr
  %_64.i.i = inttoptr i64 %_20.i.i to ptr
  %_67.i.i = getelementptr inbounds nuw i8, ptr %_62.i.i, i64 %xport_off.i.i
  %_69.i.i = getelementptr inbounds nuw i8, ptr %_67.i.i, i64 8
  %_68.i.i = icmp samesign ugt ptr %_69.i.i, %_64.i.i
  br i1 %_68.i.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv410parse_ipv4.exit.i, label %bb16.i.i

bb16.i.i:                                         ; preds = %bb4.i.i
  call void @llvm.lifetime.start.p0(ptr nonnull %key.i.i), !noalias !13
  %_30.i.i = load i8, ptr %_67.i.i, align 2, !noalias !13, !noundef !12
  %_29.i.i = zext i8 %_30.i.i to i16
  %279 = getelementptr inbounds nuw i8, ptr %_67.i.i, i64 1
  %_32.i.i = load i8, ptr %279, align 1, !noalias !13, !noundef !12
  %_31.i.i = zext i8 %_32.i.i to i16
  store i32 %src_ip.i.i, ptr %key.i.i, align 4, !noalias !13
  %280 = getelementptr inbounds nuw i8, ptr %key.i.i, i64 4
  store i32 %dst_ip.i.i, ptr %280, align 4, !noalias !13
  %281 = getelementptr inbounds nuw i8, ptr %key.i.i, i64 8
  store i16 %_29.i.i, ptr %281, align 4, !noalias !13
  %282 = getelementptr inbounds nuw i8, ptr %key.i.i, i64 10
  store i16 %_31.i.i, ptr %282, align 2, !noalias !13
  %283 = getelementptr inbounds nuw i8, ptr %key.i.i, i64 12
  store i8 1, ptr %283, align 4, !noalias !13
  %284 = getelementptr inbounds nuw i8, ptr %key.i.i, i64 13
  store i8 0, ptr %284, align 1, !noalias !13
  %_33.sroa.4.0..sroa_idx.i.i = getelementptr inbounds nuw i8, ptr %key.i.i, i64 14
  store i8 0, ptr %_33.sroa.4.0..sroa_idx.i.i, align 2, !noalias !13
  %_33.sroa.5.0..sroa_idx.i.i = getelementptr inbounds nuw i8, ptr %key.i.i, i64 15
  store i8 0, ptr %_33.sroa.5.0..sroa_idx.i.i, align 1, !noalias !13
  %_0.i9 = call noundef ptr inttoptr (i64 1 to ptr)(ptr noundef nonnull @FLOW_METRICS, ptr noundef nonnull readonly align 4 dereferenceable(16) %key.i.i) #5, !noalias !13
  %_13.i.i.i = icmp eq ptr %_0.i9, null
  br i1 %_13.i.i.i, label %bb3.i.i.i, label %bb4.i.i.i

bb4.i.i.i:                                        ; preds = %bb16.i.i
  %285 = getelementptr inbounds nuw i8, ptr %_0.i9, i64 8
  %286 = load <2 x i64>, ptr %_0.i9, align 8, !noalias !13
  %287 = insertelement <2 x i64> <i64 poison, i64 1>, i64 %_19.i.i, i64 0
  %288 = add <2 x i64> %286, %287
  %289 = extractelement <2 x i64> %288, i64 0
  store i64 %289, ptr %_0.i9, align 8, !noalias !13
  %290 = extractelement <2 x i64> %288, i64 1
  store i64 %290, ptr %285, align 8, !noalias !13
  br label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics14update_metrics.exit.i.i

bb3.i.i.i:                                        ; preds = %bb16.i.i
  call void @llvm.lifetime.start.p0(ptr nonnull %fresh.i.i.i), !noalias !69
  store i64 %_19.i.i, ptr %fresh.i.i.i, align 8, !noalias !69
  %_24.i.i.sroa.4.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 8
  store i64 1, ptr %_24.i.i.sroa.4.0.fresh.i.i.sroa_idx.i, align 8, !noalias !69
  %_24.i.i.sroa.5.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 16
  store i8 0, ptr %_24.i.i.sroa.5.0.fresh.i.i.sroa_idx.i, align 8, !noalias !69
  %_24.i.i.sroa.6.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 17
  store i8 0, ptr %_24.i.i.sroa.6.0.fresh.i.i.sroa_idx.i, align 1, !noalias !69
  %_24.i.i.sroa.7.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 18
  store i16 0, ptr %_24.i.i.sroa.7.0.fresh.i.i.sroa_idx.i, align 2, !noalias !69
  %_24.i.i.sroa.8.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 20
  store i32 0, ptr %_24.i.i.sroa.8.0.fresh.i.i.sroa_idx.i, align 4, !noalias !69
  %_24.i.i.sroa.9.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 24
  store i8 0, ptr %_24.i.i.sroa.9.0.fresh.i.i.sroa_idx.i, align 8, !noalias !69
  %_24.i.i.sroa.10.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 25
  store i8 0, ptr %_24.i.i.sroa.10.0.fresh.i.i.sroa_idx.i, align 1, !noalias !69
  %_24.i.i.sroa.11.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 26
  store i8 0, ptr %_24.i.i.sroa.11.0.fresh.i.i.sroa_idx.i, align 2, !noalias !69
  %_24.i.i.sroa.12.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 27
  store i8 0, ptr %_24.i.i.sroa.12.0.fresh.i.i.sroa_idx.i, align 1, !noalias !69
  %_24.i.i.sroa.13.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 28
  store i8 0, ptr %_24.i.i.sroa.13.0.fresh.i.i.sroa_idx.i, align 4, !noalias !69
  %_24.i.i.sroa.14.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 29
  store i8 0, ptr %_24.i.i.sroa.14.0.fresh.i.i.sroa_idx.i, align 1, !noalias !69
  %_24.i.i.sroa.15.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 30
  store i8 0, ptr %_24.i.i.sroa.15.0.fresh.i.i.sroa_idx.i, align 2, !noalias !69
  %_24.i.i.sroa.16.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 31
  store i8 0, ptr %_24.i.i.sroa.16.0.fresh.i.i.sroa_idx.i, align 1, !noalias !69
  %_24.i.i.sroa.17.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 32
  store i8 0, ptr %_24.i.i.sroa.17.0.fresh.i.i.sroa_idx.i, align 8, !noalias !69
  %_24.i.i.sroa.18.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 33
  store i8 0, ptr %_24.i.i.sroa.18.0.fresh.i.i.sroa_idx.i, align 1, !noalias !69
  %_24.i.i.sroa.19.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 34
  store i8 0, ptr %_24.i.i.sroa.19.0.fresh.i.i.sroa_idx.i, align 2, !noalias !69
  %_24.i.i.sroa.20.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 35
  store i8 0, ptr %_24.i.i.sroa.20.0.fresh.i.i.sroa_idx.i, align 1, !noalias !69
  %_24.i.i.sroa.21.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 36
  store i8 0, ptr %_24.i.i.sroa.21.0.fresh.i.i.sroa_idx.i, align 4, !noalias !69
  %_24.i.i.sroa.22.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 37
  store i8 0, ptr %_24.i.i.sroa.22.0.fresh.i.i.sroa_idx.i, align 1, !noalias !69
  %_24.i.i.sroa.23.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 38
  store i8 0, ptr %_24.i.i.sroa.23.0.fresh.i.i.sroa_idx.i, align 2, !noalias !69
  %_24.i.i.sroa.24.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 39
  store i8 0, ptr %_24.i.i.sroa.24.0.fresh.i.i.sroa_idx.i, align 1, !noalias !69
  %_24.i.i.sroa.25.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 40
  store i8 0, ptr %_24.i.i.sroa.25.0.fresh.i.i.sroa_idx.i, align 8, !noalias !69
  %_24.i.i.sroa.26.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 41
  store i8 0, ptr %_24.i.i.sroa.26.0.fresh.i.i.sroa_idx.i, align 1, !noalias !69
  %_24.i.i.sroa.27.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 42
  store i8 0, ptr %_24.i.i.sroa.27.0.fresh.i.i.sroa_idx.i, align 2, !noalias !69
  %_24.i.i.sroa.28.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 43
  store i8 0, ptr %_24.i.i.sroa.28.0.fresh.i.i.sroa_idx.i, align 1, !noalias !69
  %_24.i.i.sroa.29.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 44
  store i8 0, ptr %_24.i.i.sroa.29.0.fresh.i.i.sroa_idx.i, align 4, !noalias !69
  %_24.i.i.sroa.30.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 45
  store i8 0, ptr %_24.i.i.sroa.30.0.fresh.i.i.sroa_idx.i, align 1, !noalias !69
  %_24.i.i.sroa.31.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 46
  store i8 0, ptr %_24.i.i.sroa.31.0.fresh.i.i.sroa_idx.i, align 2, !noalias !69
  %_24.i.i.sroa.32.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 47
  store i8 0, ptr %_24.i.i.sroa.32.0.fresh.i.i.sroa_idx.i, align 1, !noalias !69
  %_24.i.i.sroa.33.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 48
  store i8 0, ptr %_24.i.i.sroa.33.0.fresh.i.i.sroa_idx.i, align 8, !noalias !69
  %_24.i.i.sroa.34.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 49
  store i8 0, ptr %_24.i.i.sroa.34.0.fresh.i.i.sroa_idx.i, align 1, !noalias !69
  %_24.i.i.sroa.35.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 50
  store i8 0, ptr %_24.i.i.sroa.35.0.fresh.i.i.sroa_idx.i, align 2, !noalias !69
  %_24.i.i.sroa.36.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 51
  store i8 0, ptr %_24.i.i.sroa.36.0.fresh.i.i.sroa_idx.i, align 1, !noalias !69
  %_24.i.i.sroa.37.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 52
  store i8 0, ptr %_24.i.i.sroa.37.0.fresh.i.i.sroa_idx.i, align 4, !noalias !69
  %_24.i.i.sroa.38.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 53
  store i8 0, ptr %_24.i.i.sroa.38.0.fresh.i.i.sroa_idx.i, align 1, !noalias !69
  %_24.i.i.sroa.39.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 54
  store i8 0, ptr %_24.i.i.sroa.39.0.fresh.i.i.sroa_idx.i, align 2, !noalias !69
  %_24.i.i.sroa.40.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 55
  store i8 0, ptr %_24.i.i.sroa.40.0.fresh.i.i.sroa_idx.i, align 1, !noalias !69
  %_24.i.i.sroa.41.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 56
  store i8 0, ptr %_24.i.i.sroa.41.0.fresh.i.i.sroa_idx.i, align 8, !noalias !69
  %_24.i.i.sroa.42.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 57
  store i8 0, ptr %_24.i.i.sroa.42.0.fresh.i.i.sroa_idx.i, align 1, !noalias !69
  %_24.i.i.sroa.43.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 58
  store i8 0, ptr %_24.i.i.sroa.43.0.fresh.i.i.sroa_idx.i, align 2, !noalias !69
  %_24.i.i.sroa.44.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 59
  store i8 0, ptr %_24.i.i.sroa.44.0.fresh.i.i.sroa_idx.i, align 1, !noalias !69
  %_24.i.i.sroa.45.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 60
  store i8 0, ptr %_24.i.i.sroa.45.0.fresh.i.i.sroa_idx.i, align 4, !noalias !69
  %_24.i.i.sroa.46.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 61
  store i8 0, ptr %_24.i.i.sroa.46.0.fresh.i.i.sroa_idx.i, align 1, !noalias !69
  %_24.i.i.sroa.47.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 62
  store i8 0, ptr %_24.i.i.sroa.47.0.fresh.i.i.sroa_idx.i, align 2, !noalias !69
  %_24.i.i.sroa.48.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 63
  store i8 0, ptr %_24.i.i.sroa.48.0.fresh.i.i.sroa_idx.i, align 1, !noalias !69
  %_24.i.i.sroa.49.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 64
  store i8 0, ptr %_24.i.i.sroa.49.0.fresh.i.i.sroa_idx.i, align 8, !noalias !69
  %_24.i.i.sroa.50.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 65
  store i8 0, ptr %_24.i.i.sroa.50.0.fresh.i.i.sroa_idx.i, align 1, !noalias !69
  %_24.i.i.sroa.51.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 66
  store i8 0, ptr %_24.i.i.sroa.51.0.fresh.i.i.sroa_idx.i, align 2, !noalias !69
  %_24.i.i.sroa.52.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 67
  store i8 0, ptr %_24.i.i.sroa.52.0.fresh.i.i.sroa_idx.i, align 1, !noalias !69
  %_24.i.i.sroa.53.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 68
  store i8 0, ptr %_24.i.i.sroa.53.0.fresh.i.i.sroa_idx.i, align 4, !noalias !69
  %_24.i.i.sroa.54.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 69
  store i8 0, ptr %_24.i.i.sroa.54.0.fresh.i.i.sroa_idx.i, align 1, !noalias !69
  %_24.i.i.sroa.55.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 70
  store i8 0, ptr %_24.i.i.sroa.55.0.fresh.i.i.sroa_idx.i, align 2, !noalias !69
  %_24.i.i.sroa.56.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 71
  store i8 0, ptr %_24.i.i.sroa.56.0.fresh.i.i.sroa_idx.i, align 1, !noalias !69
  %_24.i.i.sroa.57.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 72
  store i8 0, ptr %_24.i.i.sroa.57.0.fresh.i.i.sroa_idx.i, align 8, !noalias !69
  %_24.i.i.sroa.58.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 73
  store i8 0, ptr %_24.i.i.sroa.58.0.fresh.i.i.sroa_idx.i, align 1, !noalias !69
  %_24.i.i.sroa.59.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 74
  store i8 0, ptr %_24.i.i.sroa.59.0.fresh.i.i.sroa_idx.i, align 2, !noalias !69
  %_24.i.i.sroa.60.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 75
  store i8 0, ptr %_24.i.i.sroa.60.0.fresh.i.i.sroa_idx.i, align 1, !noalias !69
  %_24.i.i.sroa.61.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 76
  store i8 0, ptr %_24.i.i.sroa.61.0.fresh.i.i.sroa_idx.i, align 4, !noalias !69
  %_24.i.i.sroa.62.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 77
  store i8 0, ptr %_24.i.i.sroa.62.0.fresh.i.i.sroa_idx.i, align 1, !noalias !69
  %_24.i.i.sroa.63.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 78
  store i8 0, ptr %_24.i.i.sroa.63.0.fresh.i.i.sroa_idx.i, align 2, !noalias !69
  %_24.i.i.sroa.64.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 79
  store i8 0, ptr %_24.i.i.sroa.64.0.fresh.i.i.sroa_idx.i, align 1, !noalias !69
  %_24.i.i.sroa.65.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 80
  store i8 0, ptr %_24.i.i.sroa.65.0.fresh.i.i.sroa_idx.i, align 8, !noalias !69
  %_24.i.i.sroa.66.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 81
  store i8 0, ptr %_24.i.i.sroa.66.0.fresh.i.i.sroa_idx.i, align 1, !noalias !69
  %_24.i.i.sroa.67.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 82
  store i8 0, ptr %_24.i.i.sroa.67.0.fresh.i.i.sroa_idx.i, align 2, !noalias !69
  %_24.i.i.sroa.68.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 83
  store i8 0, ptr %_24.i.i.sroa.68.0.fresh.i.i.sroa_idx.i, align 1, !noalias !69
  %_24.i.i.sroa.69.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 84
  store i8 0, ptr %_24.i.i.sroa.69.0.fresh.i.i.sroa_idx.i, align 4, !noalias !69
  %_24.i.i.sroa.70.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 85
  store i8 0, ptr %_24.i.i.sroa.70.0.fresh.i.i.sroa_idx.i, align 1, !noalias !69
  %_24.i.i.sroa.71.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 86
  store i8 0, ptr %_24.i.i.sroa.71.0.fresh.i.i.sroa_idx.i, align 2, !noalias !69
  %_24.i.i.sroa.72.0.fresh.i.i.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i.i, i64 87
  store i8 0, ptr %_24.i.i.sroa.72.0.fresh.i.i.sroa_idx.i, align 1, !noalias !69
  %_0.i10 = call noundef i64 inttoptr (i64 2 to ptr)(ptr noundef nonnull @FLOW_METRICS, ptr noundef nonnull readonly align 4 dereferenceable(16) %key.i.i, ptr noundef nonnull %fresh.i.i.i, i64 noundef 0) #5
  call void @llvm.lifetime.end.p0(ptr nonnull %fresh.i.i.i), !noalias !69
  br label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics14update_metrics.exit.i.i

_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics14update_metrics.exit.i.i: ; preds = %bb3.i.i.i, %bb4.i.i.i
  call void @llvm.lifetime.end.p0(ptr nonnull %key.i.i), !noalias !13
  br label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv410parse_ipv4.exit.i

_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv410parse_ipv4.exit.i: ; preds = %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics14update_metrics.exit.i.i, %bb4.i.i, %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i446.i, %bb5.i420.i, %bb4.i512.i, %bb15.i7.i206.i, %bb8.i.i197.i, %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i336.i, %bb5.i316.i, %bb4.i402.i, %bb12.i11.i260.i, %bb10.i10.i256.i, %bb2.i6.i186.i, %bb3.i.i245.i, %bb7.i183.i, %bb5.i180.i, %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i115.i, %bb3.i93.i, %bb1.i274.i, %bb13.i.i, %bb11.i.i, %bb3.i.i
  %_0.sroa.8.0.i.i = phi i64 [ 1, %bb3.i.i ], [ 8589934592, %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics14update_metrics.exit.i.i ], [ 4294967296, %bb11.i.i ], [ 1, %bb4.i.i ], [ 8589934592, %bb13.i.i ], [ 1, %bb3.i93.i ], [ 8589934592, %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i115.i ], [ 1, %bb1.i274.i ], [ 8589934592, %bb5.i180.i ], [ 1, %bb2.i6.i186.i ], [ 8589934592, %bb7.i183.i ], [ 4294967296, %bb8.i.i197.i ], [ 1, %bb3.i.i245.i ], [ 4294967296, %bb10.i10.i256.i ], [ 8589934592, %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i336.i ], [ 8589934592, %bb12.i11.i260.i ], [ 8589934593, %bb4.i402.i ], [ 8589934593, %bb5.i316.i ], [ 8589934592, %bb15.i7.i206.i ], [ 8589934593, %bb4.i512.i ], [ 8589934593, %bb5.i420.i ], [ 8589934592, %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i446.i ]
  %.sroa.4.0.extract.shift.i.i = and i64 %_0.sroa.8.0.i.i, 12884901888
  br label %_RNvNvCsiBg6FOfWNuR_9mizn_ebpf9mizn_ebpf9mizn_ebpf.exit

bb2.i.i:                                          ; preds = %bb7.i.i
  %_49.i.i = getelementptr inbounds nuw i8, ptr %_8.i.i, i64 54
  %_48.i.i = icmp samesign ugt ptr %_49.i.i, %_10.i.i
  br i1 %_48.i.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv610parse_ipv6.exit.i, label %bb11.i14.i

bb11.i14.i:                                       ; preds = %bb2.i.i
  %_59.i15.i = getelementptr inbounds nuw i8, ptr %_8.i.i, i64 22
  %_0.i11 = tail call noundef ptr inttoptr (i64 1 to ptr)(ptr noundef nonnull @BLOCKLIST_V6, ptr noundef nonnull %_59.i15.i) #5, !noalias !72
  %_60.i16.i = icmp eq ptr %_0.i11, null
  br i1 %_60.i16.i, label %bb13.i18.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv610parse_ipv6.exit.i

bb13.i18.i:                                       ; preds = %bb11.i14.i
  %291 = getelementptr inbounds nuw i8, ptr %_8.i.i, i64 20
  %next.i.i = load i8, ptr %291, align 2, !noalias !72, !noundef !12
  %_64.i19.i = load i32, ptr %0, align 4, !noalias !72, !noundef !12
  %_14.i20.i = zext i32 %_64.i19.i to i64
  %_66.i.i = load i32, ptr %ctx, align 4, !noalias !72, !noundef !12
  %_15.i21.i = zext i32 %_66.i.i to i64
  %_13.i22.i = sub nsw i64 %_14.i20.i, %_15.i21.i
  %292 = getelementptr inbounds nuw i8, ptr %_8.i.i, i64 34
  %_18.i.i = load i8, ptr %292, align 4, !noalias !72, !noundef !12
  %293 = getelementptr inbounds nuw i8, ptr %_8.i.i, i64 35
  %_19.i23.i = load i8, ptr %293, align 1, !noalias !72, !noundef !12
  %294 = getelementptr inbounds nuw i8, ptr %_8.i.i, i64 36
  %_20.i24.i = load i8, ptr %294, align 2, !noalias !72, !noundef !12
  %295 = getelementptr inbounds nuw i8, ptr %_8.i.i, i64 37
  %_21.i25.i = load i8, ptr %295, align 1, !noalias !72, !noundef !12
  %_17.sroa.6.0.insert.ext.i.i = zext i8 %_21.i25.i to i32
  %_17.sroa.6.0.insert.shift.i.i = shl nuw i32 %_17.sroa.6.0.insert.ext.i.i, 24
  %_17.sroa.5.0.insert.ext.i.i = zext i8 %_20.i24.i to i32
  %_17.sroa.5.0.insert.shift.i.i = shl nuw nsw i32 %_17.sroa.5.0.insert.ext.i.i, 16
  %_17.sroa.4.0.insert.ext.i.i = zext i8 %_19.i23.i to i32
  %_17.sroa.4.0.insert.shift.i.i = shl nuw nsw i32 %_17.sroa.4.0.insert.ext.i.i, 8
  %_17.sroa.0.0.insert.ext.i.i = zext i8 %_18.i.i to i32
  %_17.sroa.5.0.insert.insert.i.i = or disjoint i32 %_17.sroa.4.0.insert.shift.i.i, %_17.sroa.0.0.insert.ext.i.i
  %_17.sroa.4.0.insert.insert.i.i = or disjoint i32 %_17.sroa.5.0.insert.insert.i.i, %_17.sroa.5.0.insert.shift.i.i
  %_17.sroa.0.0.insert.insert.i.i = or disjoint i32 %_17.sroa.4.0.insert.insert.i.i, %_17.sroa.6.0.insert.shift.i.i
  %src_lo.i.i = tail call i32 @llvm.bswap.i32(i32 %_17.sroa.0.0.insert.insert.i.i)
  %296 = getelementptr inbounds nuw i8, ptr %_8.i.i, i64 50
  %_24.i.i = load i8, ptr %296, align 4, !noalias !72, !noundef !12
  %297 = getelementptr inbounds nuw i8, ptr %_8.i.i, i64 51
  %_25.i.i = load i8, ptr %297, align 1, !noalias !72, !noundef !12
  %298 = getelementptr inbounds nuw i8, ptr %_8.i.i, i64 52
  %_26.i.i = load i8, ptr %298, align 2, !noalias !72, !noundef !12
  %299 = getelementptr inbounds nuw i8, ptr %_8.i.i, i64 53
  %_27.i.i = load i8, ptr %299, align 1, !noalias !72, !noundef !12
  %_23.sroa.6.0.insert.ext.i.i = zext i8 %_27.i.i to i32
  %_23.sroa.6.0.insert.shift.i.i = shl nuw i32 %_23.sroa.6.0.insert.ext.i.i, 24
  %_23.sroa.5.0.insert.ext.i.i = zext i8 %_26.i.i to i32
  %_23.sroa.5.0.insert.shift.i.i = shl nuw nsw i32 %_23.sroa.5.0.insert.ext.i.i, 16
  %_23.sroa.4.0.insert.ext.i.i = zext i8 %_25.i.i to i32
  %_23.sroa.4.0.insert.shift.i.i = shl nuw nsw i32 %_23.sroa.4.0.insert.ext.i.i, 8
  %_23.sroa.0.0.insert.ext.i.i = zext i8 %_24.i.i to i32
  %_23.sroa.5.0.insert.insert.i.i = or disjoint i32 %_23.sroa.4.0.insert.shift.i.i, %_23.sroa.0.0.insert.ext.i.i
  %_23.sroa.4.0.insert.insert.i.i = or disjoint i32 %_23.sroa.5.0.insert.insert.i.i, %_23.sroa.5.0.insert.shift.i.i
  %_23.sroa.0.0.insert.insert.i.i = or disjoint i32 %_23.sroa.4.0.insert.insert.i.i, %_23.sroa.6.0.insert.shift.i.i
  %dst_lo.i.i = tail call i32 @llvm.bswap.i32(i32 %_23.sroa.0.0.insert.insert.i.i)
  switch i8 %next.i.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv610parse_ipv6.exit.i [
    i8 6, label %bb5.i41.i
    i8 17, label %bb5.i41.i
    i8 58, label %bb4.i26.i
  ]

bb5.i41.i:                                        ; preds = %bb13.i18.i, %bb13.i18.i
  %300 = icmp eq i8 %next.i.i, 6
  %_37.i49.i = inttoptr i64 %_15.i21.i to ptr
  %_39.i50.i = inttoptr i64 %_14.i20.i to ptr
  %_42.i51.i = getelementptr i8, ptr %_37.i49.i, i64 54
  br i1 %300, label %bb1.i.i, label %bb3.i52.i

bb1.i.i:                                          ; preds = %bb5.i41.i
  %_44.i74.i = getelementptr i8, ptr %_37.i49.i, i64 74
  %_43.i75.i = icmp samesign ugt ptr %_44.i74.i, %_39.i50.i
  br i1 %_43.i75.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv610parse_ipv6.exit.i, label %bb17.i.i

bb3.i52.i:                                        ; preds = %bb5.i41.i
  %_59.i53.i = getelementptr i8, ptr %_37.i49.i, i64 62
  %_58.i54.i = icmp samesign ugt ptr %_59.i53.i, %_39.i50.i
  br i1 %_58.i54.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv610parse_ipv6.exit.i, label %bb21.i.i

bb17.i.i:                                         ; preds = %bb1.i.i
  %301 = getelementptr i8, ptr %_37.i49.i, i64 66
  %_12.i.i = load i8, ptr %301, align 4, !noalias !75, !noundef !12
  %302 = lshr i8 %_12.i.i, 2
  %303 = and i8 %302, 60
  %_14.i76.i = load i16, ptr %_42.i51.i, align 4, !noalias !75, !noundef !12
  %304 = tail call i16 @llvm.bswap.i16(i16 %_14.i76.i)
  %305 = getelementptr i8, ptr %_37.i49.i, i64 56
  %_16.i77.i = load i16, ptr %305, align 2, !noalias !75, !noundef !12
  %306 = tail call i16 @llvm.bswap.i16(i16 %_16.i77.i)
  %narrow777.i = add nuw nsw i8 %303, 54
  %307 = zext nneg i8 %narrow777.i to i64
  %308 = getelementptr i8, ptr %_37.i49.i, i64 67
  %309 = load i8, ptr %308, align 1, !noalias !75, !noundef !12
  br label %bb11.i57.i

bb11.i57.i:                                       ; preds = %bb10.i.i, %bb17.i.i
  %src_port.sroa.0.0.i.i = phi i16 [ %304, %bb17.i.i ], [ %386, %bb10.i.i ]
  %dst_port.sroa.0.0.i.i = phi i16 [ %306, %bb17.i.i ], [ %387, %bb10.i.i ]
  %payload_off.sroa.0.0.i.i = phi i64 [ %307, %bb17.i.i ], [ 62, %bb10.i.i ]
  %flags.sroa.0.0.i.i = phi i8 [ %309, %bb17.i.i ], [ 0, %bb10.i.i ]
  call void @llvm.lifetime.start.p0(ptr nonnull %key.i44.i), !noalias !75
  store i32 %src_lo.i.i, ptr %key.i44.i, align 4, !noalias !75
  %310 = getelementptr inbounds nuw i8, ptr %key.i44.i, i64 4
  store i32 %dst_lo.i.i, ptr %310, align 4, !noalias !75
  %311 = getelementptr inbounds nuw i8, ptr %key.i44.i, i64 8
  store i16 %src_port.sroa.0.0.i.i, ptr %311, align 4, !noalias !75
  %312 = getelementptr inbounds nuw i8, ptr %key.i44.i, i64 10
  store i16 %dst_port.sroa.0.0.i.i, ptr %312, align 2, !noalias !75
  %313 = getelementptr inbounds nuw i8, ptr %key.i44.i, i64 12
  store i8 %next.i.i, ptr %313, align 4, !noalias !75
  %314 = getelementptr inbounds nuw i8, ptr %key.i44.i, i64 13
  store i8 0, ptr %314, align 1, !noalias !75
  %_33.sroa.4.0..sroa_idx.i60.i = getelementptr inbounds nuw i8, ptr %key.i44.i, i64 14
  store i8 0, ptr %_33.sroa.4.0..sroa_idx.i60.i, align 2, !noalias !75
  %_33.sroa.5.0..sroa_idx.i61.i = getelementptr inbounds nuw i8, ptr %key.i44.i, i64 15
  store i8 0, ptr %_33.sroa.5.0..sroa_idx.i61.i, align 1, !noalias !75
  %_0.i12 = call noundef ptr inttoptr (i64 1 to ptr)(ptr noundef nonnull @FLOW_METRICS, ptr noundef nonnull readonly align 4 dereferenceable(16) %key.i44.i) #5, !noalias !79
  %_20.i.i63.i = icmp eq ptr %_0.i12, null
  br i1 %_20.i.i63.i, label %bb10.i.i.i, label %bb11.i.i.i

bb11.i.i.i:                                       ; preds = %bb11.i57.i
  %315 = getelementptr inbounds nuw i8, ptr %_0.i12, i64 8
  %316 = load <2 x i64>, ptr %_0.i12, align 8, !noalias !79
  %317 = insertelement <2 x i64> <i64 poison, i64 1>, i64 %_13.i22.i, i64 0
  %318 = add <2 x i64> %316, %317
  %319 = extractelement <2 x i64> %318, i64 0
  store i64 %319, ptr %_0.i12, align 8, !noalias !79
  %320 = extractelement <2 x i64> %318, i64 1
  store i64 %320, ptr %315, align 8, !noalias !79
  %321 = getelementptr inbounds nuw i8, ptr %_0.i12, i64 16
  %322 = load i8, ptr %321, align 8, !noalias !79, !noundef !12
  %323 = or i8 %322, %flags.sroa.0.0.i.i
  store i8 %323, ptr %321, align 8, !noalias !79
  %324 = icmp eq i16 %dst_port.sroa.0.0.i.i, 443
  %or.cond.i.i.i = and i1 %300, %324
  br i1 %or.cond.i.i.i, label %bb2.i.i.i, label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i.i

bb10.i.i.i:                                       ; preds = %bb11.i57.i
  call void @llvm.lifetime.start.p0(ptr nonnull %fresh.i.i43.i), !noalias !82
  store i64 %_13.i22.i, ptr %fresh.i.i43.i, align 8, !noalias !82
  %_31.i.i.sroa.4.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 8
  store i64 1, ptr %_31.i.i.sroa.4.0.fresh.i.i43.sroa_idx.i, align 8, !noalias !82
  %_31.i.i.sroa.5.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 16
  store i8 %flags.sroa.0.0.i.i, ptr %_31.i.i.sroa.5.0.fresh.i.i43.sroa_idx.i, align 8, !noalias !82
  %_31.i.i.sroa.6.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 17
  store i8 0, ptr %_31.i.i.sroa.6.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !82
  %_31.i.i.sroa.7.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 18
  store i16 0, ptr %_31.i.i.sroa.7.0.fresh.i.i43.sroa_idx.i, align 2, !noalias !82
  %_31.i.i.sroa.8.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 20
  store i32 0, ptr %_31.i.i.sroa.8.0.fresh.i.i43.sroa_idx.i, align 4, !noalias !82
  %_31.i.i.sroa.9.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 24
  store i8 0, ptr %_31.i.i.sroa.9.0.fresh.i.i43.sroa_idx.i, align 8, !noalias !82
  %_31.i.i.sroa.10.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 25
  store i8 0, ptr %_31.i.i.sroa.10.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !82
  %_31.i.i.sroa.11.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 26
  store i8 0, ptr %_31.i.i.sroa.11.0.fresh.i.i43.sroa_idx.i, align 2, !noalias !82
  %_31.i.i.sroa.12.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 27
  store i8 0, ptr %_31.i.i.sroa.12.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !82
  %_31.i.i.sroa.13.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 28
  store i8 0, ptr %_31.i.i.sroa.13.0.fresh.i.i43.sroa_idx.i, align 4, !noalias !82
  %_31.i.i.sroa.14.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 29
  store i8 0, ptr %_31.i.i.sroa.14.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !82
  %_31.i.i.sroa.15.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 30
  store i8 0, ptr %_31.i.i.sroa.15.0.fresh.i.i43.sroa_idx.i, align 2, !noalias !82
  %_31.i.i.sroa.16.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 31
  store i8 0, ptr %_31.i.i.sroa.16.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !82
  %_31.i.i.sroa.17.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 32
  store i8 0, ptr %_31.i.i.sroa.17.0.fresh.i.i43.sroa_idx.i, align 8, !noalias !82
  %_31.i.i.sroa.18.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 33
  store i8 0, ptr %_31.i.i.sroa.18.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !82
  %_31.i.i.sroa.19.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 34
  store i8 0, ptr %_31.i.i.sroa.19.0.fresh.i.i43.sroa_idx.i, align 2, !noalias !82
  %_31.i.i.sroa.20.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 35
  store i8 0, ptr %_31.i.i.sroa.20.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !82
  %_31.i.i.sroa.21.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 36
  store i8 0, ptr %_31.i.i.sroa.21.0.fresh.i.i43.sroa_idx.i, align 4, !noalias !82
  %_31.i.i.sroa.22.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 37
  store i8 0, ptr %_31.i.i.sroa.22.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !82
  %_31.i.i.sroa.23.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 38
  store i8 0, ptr %_31.i.i.sroa.23.0.fresh.i.i43.sroa_idx.i, align 2, !noalias !82
  %_31.i.i.sroa.24.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 39
  store i8 0, ptr %_31.i.i.sroa.24.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !82
  %_31.i.i.sroa.25.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 40
  store i8 0, ptr %_31.i.i.sroa.25.0.fresh.i.i43.sroa_idx.i, align 8, !noalias !82
  %_31.i.i.sroa.26.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 41
  store i8 0, ptr %_31.i.i.sroa.26.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !82
  %_31.i.i.sroa.27.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 42
  store i8 0, ptr %_31.i.i.sroa.27.0.fresh.i.i43.sroa_idx.i, align 2, !noalias !82
  %_31.i.i.sroa.28.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 43
  store i8 0, ptr %_31.i.i.sroa.28.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !82
  %_31.i.i.sroa.29.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 44
  store i8 0, ptr %_31.i.i.sroa.29.0.fresh.i.i43.sroa_idx.i, align 4, !noalias !82
  %_31.i.i.sroa.30.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 45
  store i8 0, ptr %_31.i.i.sroa.30.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !82
  %_31.i.i.sroa.31.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 46
  store i8 0, ptr %_31.i.i.sroa.31.0.fresh.i.i43.sroa_idx.i, align 2, !noalias !82
  %_31.i.i.sroa.32.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 47
  store i8 0, ptr %_31.i.i.sroa.32.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !82
  %_31.i.i.sroa.33.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 48
  store i8 0, ptr %_31.i.i.sroa.33.0.fresh.i.i43.sroa_idx.i, align 8, !noalias !82
  %_31.i.i.sroa.34.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 49
  store i8 0, ptr %_31.i.i.sroa.34.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !82
  %_31.i.i.sroa.35.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 50
  store i8 0, ptr %_31.i.i.sroa.35.0.fresh.i.i43.sroa_idx.i, align 2, !noalias !82
  %_31.i.i.sroa.36.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 51
  store i8 0, ptr %_31.i.i.sroa.36.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !82
  %_31.i.i.sroa.37.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 52
  store i8 0, ptr %_31.i.i.sroa.37.0.fresh.i.i43.sroa_idx.i, align 4, !noalias !82
  %_31.i.i.sroa.38.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 53
  store i8 0, ptr %_31.i.i.sroa.38.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !82
  %_31.i.i.sroa.39.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 54
  store i8 0, ptr %_31.i.i.sroa.39.0.fresh.i.i43.sroa_idx.i, align 2, !noalias !82
  %_31.i.i.sroa.40.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 55
  store i8 0, ptr %_31.i.i.sroa.40.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !82
  %_31.i.i.sroa.41.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 56
  store i8 0, ptr %_31.i.i.sroa.41.0.fresh.i.i43.sroa_idx.i, align 8, !noalias !82
  %_31.i.i.sroa.42.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 57
  store i8 0, ptr %_31.i.i.sroa.42.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !82
  %_31.i.i.sroa.43.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 58
  store i8 0, ptr %_31.i.i.sroa.43.0.fresh.i.i43.sroa_idx.i, align 2, !noalias !82
  %_31.i.i.sroa.44.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 59
  store i8 0, ptr %_31.i.i.sroa.44.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !82
  %_31.i.i.sroa.45.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 60
  store i8 0, ptr %_31.i.i.sroa.45.0.fresh.i.i43.sroa_idx.i, align 4, !noalias !82
  %_31.i.i.sroa.46.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 61
  store i8 0, ptr %_31.i.i.sroa.46.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !82
  %_31.i.i.sroa.47.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 62
  store i8 0, ptr %_31.i.i.sroa.47.0.fresh.i.i43.sroa_idx.i, align 2, !noalias !82
  %_31.i.i.sroa.48.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 63
  store i8 0, ptr %_31.i.i.sroa.48.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !82
  %_31.i.i.sroa.49.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 64
  store i8 0, ptr %_31.i.i.sroa.49.0.fresh.i.i43.sroa_idx.i, align 8, !noalias !82
  %_31.i.i.sroa.50.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 65
  store i8 0, ptr %_31.i.i.sroa.50.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !82
  %_31.i.i.sroa.51.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 66
  store i8 0, ptr %_31.i.i.sroa.51.0.fresh.i.i43.sroa_idx.i, align 2, !noalias !82
  %_31.i.i.sroa.52.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 67
  store i8 0, ptr %_31.i.i.sroa.52.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !82
  %_31.i.i.sroa.53.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 68
  store i8 0, ptr %_31.i.i.sroa.53.0.fresh.i.i43.sroa_idx.i, align 4, !noalias !82
  %_31.i.i.sroa.54.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 69
  store i8 0, ptr %_31.i.i.sroa.54.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !82
  %_31.i.i.sroa.55.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 70
  store i8 0, ptr %_31.i.i.sroa.55.0.fresh.i.i43.sroa_idx.i, align 2, !noalias !82
  %_31.i.i.sroa.56.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 71
  store i8 0, ptr %_31.i.i.sroa.56.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !82
  %_31.i.i.sroa.57.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 72
  store i8 0, ptr %_31.i.i.sroa.57.0.fresh.i.i43.sroa_idx.i, align 8, !noalias !82
  %_31.i.i.sroa.58.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 73
  store i8 0, ptr %_31.i.i.sroa.58.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !82
  %_31.i.i.sroa.59.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 74
  store i8 0, ptr %_31.i.i.sroa.59.0.fresh.i.i43.sroa_idx.i, align 2, !noalias !82
  %_31.i.i.sroa.60.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 75
  store i8 0, ptr %_31.i.i.sroa.60.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !82
  %_31.i.i.sroa.61.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 76
  store i8 0, ptr %_31.i.i.sroa.61.0.fresh.i.i43.sroa_idx.i, align 4, !noalias !82
  %_31.i.i.sroa.62.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 77
  store i8 0, ptr %_31.i.i.sroa.62.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !82
  %_31.i.i.sroa.63.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 78
  store i8 0, ptr %_31.i.i.sroa.63.0.fresh.i.i43.sroa_idx.i, align 2, !noalias !82
  %_31.i.i.sroa.64.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 79
  store i8 0, ptr %_31.i.i.sroa.64.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !82
  %_31.i.i.sroa.65.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 80
  store i8 0, ptr %_31.i.i.sroa.65.0.fresh.i.i43.sroa_idx.i, align 8, !noalias !82
  %_31.i.i.sroa.66.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 81
  store i8 0, ptr %_31.i.i.sroa.66.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !82
  %_31.i.i.sroa.67.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 82
  store i8 0, ptr %_31.i.i.sroa.67.0.fresh.i.i43.sroa_idx.i, align 2, !noalias !82
  %_31.i.i.sroa.68.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 83
  store i8 0, ptr %_31.i.i.sroa.68.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !82
  %_31.i.i.sroa.69.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 84
  store i8 0, ptr %_31.i.i.sroa.69.0.fresh.i.i43.sroa_idx.i, align 4, !noalias !82
  %_31.i.i.sroa.70.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 85
  store i8 0, ptr %_31.i.i.sroa.70.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !82
  %_31.i.i.sroa.71.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 86
  store i8 0, ptr %_31.i.i.sroa.71.0.fresh.i.i43.sroa_idx.i, align 2, !noalias !82
  %_31.i.i.sroa.72.0.fresh.i.i43.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i43.i, i64 87
  store i8 0, ptr %_31.i.i.sroa.72.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !82
  %325 = icmp eq i16 %dst_port.sroa.0.0.i.i, 443
  %or.cond1.i.i.i = and i1 %300, %325
  br i1 %or.cond1.i.i.i, label %bb5.i.i66.i, label %bb7.i.i65.i

bb2.i.i.i:                                        ; preds = %bb11.i.i.i
  %_28.i5.i.i.i = load i32, ptr %ctx, align 4, !noalias !84, !noundef !12
  %_22.i6.i.i.i = zext i32 %_28.i5.i.i.i to i64
  %_21.i7.i.i.i = inttoptr i64 %_22.i6.i.i.i to ptr
  %_30.i8.i.i.i = load i32, ptr %0, align 4, !noalias !84, !noundef !12
  %_24.i9.i.i.i = zext i32 %_30.i8.i.i.i to i64
  %_23.i10.i.i.i = inttoptr i64 %_24.i9.i.i.i to ptr
  %_25.i11.i.i.i = getelementptr inbounds nuw i8, ptr %_21.i7.i.i.i, i64 %payload_off.sroa.0.0.i.i
  %_27.i12.i.i.i = getelementptr inbounds nuw i8, ptr %_25.i11.i.i.i, i64 1
  %_26.i13.i.i.i = icmp samesign ugt ptr %_27.i12.i.i.i, %_23.i10.i.i.i
  br i1 %_26.i13.i.i.i, label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i.i, label %bb10.i14.i.i.i

bb10.i14.i.i.i:                                   ; preds = %bb2.i.i.i
  %_6.i15.i.i.i = load i8, ptr %_25.i11.i.i.i, align 1, !noalias !84, !noundef !12
  %326 = icmp ne i8 %_6.i15.i.i.i, 22
  %_39.i17.i.i.i = getelementptr i8, ptr %_25.i11.i.i.i, i64 21
  %_38.i18.i.i.i = icmp samesign ugt ptr %_39.i17.i.i.i, %_23.i10.i.i.i
  %or.cond770.i = or i1 %_38.i18.i.i.i, %326
  br i1 %or.cond770.i, label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i.i, label %bb12.i19.i.i.i

bb12.i19.i.i.i:                                   ; preds = %bb10.i14.i.i.i
  %_37.i20.i.i.i = getelementptr i8, ptr %_25.i11.i.i.i, i64 5
  %_13.i21.i.i.i = getelementptr inbounds nuw i8, ptr %_0.i12, i64 24
  call void @llvm.memcpy.p0.p0.i64(ptr noundef nonnull align 1 dereferenceable(16) %_13.i21.i.i.i, ptr noundef nonnull align 1 dereferenceable(16) %_37.i20.i.i.i, i64 16, i1 false), !noalias !84
  %327 = getelementptr inbounds nuw i8, ptr %_0.i12, i64 25
  %328 = getelementptr inbounds nuw i8, ptr %_0.i12, i64 26
  %329 = getelementptr inbounds nuw i8, ptr %_0.i12, i64 27
  %330 = getelementptr inbounds nuw i8, ptr %_0.i12, i64 28
  %331 = getelementptr inbounds nuw i8, ptr %_0.i12, i64 29
  %332 = getelementptr inbounds nuw i8, ptr %_0.i12, i64 30
  %333 = getelementptr inbounds nuw i8, ptr %_0.i12, i64 31
  %334 = getelementptr inbounds nuw i8, ptr %_0.i12, i64 32
  %335 = getelementptr inbounds nuw i8, ptr %_0.i12, i64 33
  %336 = getelementptr inbounds nuw i8, ptr %_0.i12, i64 34
  %337 = getelementptr inbounds nuw i8, ptr %_0.i12, i64 35
  %338 = getelementptr inbounds nuw i8, ptr %_0.i12, i64 36
  %339 = getelementptr inbounds nuw i8, ptr %_0.i12, i64 37
  %340 = getelementptr inbounds nuw i8, ptr %_0.i12, i64 38
  %341 = getelementptr inbounds nuw i8, ptr %_0.i12, i64 39
  %342 = load <16 x i8>, ptr %_13.i21.i.i.i, align 8, !noalias !84
  %343 = add <16 x i8> %342, splat (i8 -32)
  %344 = icmp ult <16 x i8> %343, splat (i8 95)
  %345 = select <16 x i1> %344, <16 x i8> %342, <16 x i8> zeroinitializer
  %346 = extractelement <16 x i8> %345, i64 0
  store i8 %346, ptr %_13.i21.i.i.i, align 8, !noalias !84
  %347 = extractelement <16 x i8> %345, i64 1
  store i8 %347, ptr %327, align 1, !noalias !84
  %348 = extractelement <16 x i8> %345, i64 2
  store i8 %348, ptr %328, align 2, !noalias !84
  %349 = extractelement <16 x i8> %345, i64 3
  store i8 %349, ptr %329, align 1, !noalias !84
  %350 = extractelement <16 x i8> %345, i64 4
  store i8 %350, ptr %330, align 4, !noalias !84
  %351 = extractelement <16 x i8> %345, i64 5
  store i8 %351, ptr %331, align 1, !noalias !84
  %352 = extractelement <16 x i8> %345, i64 6
  store i8 %352, ptr %332, align 2, !noalias !84
  %353 = extractelement <16 x i8> %345, i64 7
  store i8 %353, ptr %333, align 1, !noalias !84
  %354 = extractelement <16 x i8> %345, i64 8
  store i8 %354, ptr %334, align 8, !noalias !84
  %355 = extractelement <16 x i8> %345, i64 9
  store i8 %355, ptr %335, align 1, !noalias !84
  %356 = extractelement <16 x i8> %345, i64 10
  store i8 %356, ptr %336, align 2, !noalias !84
  %357 = extractelement <16 x i8> %345, i64 11
  store i8 %357, ptr %337, align 1, !noalias !84
  %358 = extractelement <16 x i8> %345, i64 12
  store i8 %358, ptr %338, align 4, !noalias !84
  %359 = extractelement <16 x i8> %345, i64 13
  store i8 %359, ptr %339, align 1, !noalias !84
  %360 = extractelement <16 x i8> %345, i64 14
  store i8 %360, ptr %340, align 2, !noalias !84
  %361 = extractelement <16 x i8> %345, i64 15
  store i8 %361, ptr %341, align 1, !noalias !84
  br label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i.i

bb7.i.i65.i:                                      ; preds = %bb12.i.i.i.i, %bb10.i.i.i.i, %bb5.i.i66.i, %bb10.i.i.i
  %_0.i13 = call noundef i64 inttoptr (i64 2 to ptr)(ptr noundef nonnull @FLOW_METRICS, ptr noundef nonnull readonly align 4 dereferenceable(16) %key.i44.i, ptr noundef nonnull %fresh.i.i43.i, i64 noundef 0) #5
  call void @llvm.lifetime.end.p0(ptr nonnull %fresh.i.i43.i), !noalias !82
  br label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i.i

bb5.i.i66.i:                                      ; preds = %bb10.i.i.i
  %_28.i.i.i.i = load i32, ptr %ctx, align 4, !noalias !87, !noundef !12
  %_22.i.i.i.i = zext i32 %_28.i.i.i.i to i64
  %_21.i.i.i.i = inttoptr i64 %_22.i.i.i.i to ptr
  %_30.i.i.i.i = load i32, ptr %0, align 4, !noalias !87, !noundef !12
  %_24.i.i.i.i = zext i32 %_30.i.i.i.i to i64
  %_23.i.i.i.i = inttoptr i64 %_24.i.i.i.i to ptr
  %_25.i.i.i.i = getelementptr inbounds nuw i8, ptr %_21.i.i.i.i, i64 %payload_off.sroa.0.0.i.i
  %_27.i.i.i.i = getelementptr inbounds nuw i8, ptr %_25.i.i.i.i, i64 1
  %_26.i.i.i.i = icmp samesign ugt ptr %_27.i.i.i.i, %_23.i.i.i.i
  br i1 %_26.i.i.i.i, label %bb7.i.i65.i, label %bb10.i.i.i.i

bb10.i.i.i.i:                                     ; preds = %bb5.i.i66.i
  %_6.i.i.i.i = load i8, ptr %_25.i.i.i.i, align 1, !noalias !87, !noundef !12
  %362 = icmp ne i8 %_6.i.i.i.i, 22
  %_39.i.i.i.i = getelementptr i8, ptr %_25.i.i.i.i, i64 21
  %_38.i.i.i.i = icmp samesign ugt ptr %_39.i.i.i.i, %_23.i.i.i.i
  %or.cond771.i = or i1 %_38.i.i.i.i, %362
  br i1 %or.cond771.i, label %bb7.i.i65.i, label %bb12.i.i.i.i

bb12.i.i.i.i:                                     ; preds = %bb10.i.i.i.i
  %_37.i.i.i.i = getelementptr i8, ptr %_25.i.i.i.i, i64 5
  call void @llvm.memcpy.p0.p0.i64(ptr noundef nonnull align 8 dereferenceable(16) %_31.i.i.sroa.9.0.fresh.i.i43.sroa_idx.i, ptr noundef nonnull align 1 dereferenceable(16) %_37.i.i.i.i, i64 16, i1 false), !noalias !87
  %363 = load <16 x i8>, ptr %_31.i.i.sroa.9.0.fresh.i.i43.sroa_idx.i, align 8, !noalias !90
  %364 = add <16 x i8> %363, splat (i8 -32)
  %365 = icmp ult <16 x i8> %364, splat (i8 95)
  %366 = select <16 x i1> %365, <16 x i8> %363, <16 x i8> zeroinitializer
  %367 = extractelement <16 x i8> %366, i64 0
  store i8 %367, ptr %_31.i.i.sroa.9.0.fresh.i.i43.sroa_idx.i, align 8, !noalias !90
  %368 = extractelement <16 x i8> %366, i64 1
  store i8 %368, ptr %_31.i.i.sroa.10.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !90
  %369 = extractelement <16 x i8> %366, i64 2
  store i8 %369, ptr %_31.i.i.sroa.11.0.fresh.i.i43.sroa_idx.i, align 2, !noalias !90
  %370 = extractelement <16 x i8> %366, i64 3
  store i8 %370, ptr %_31.i.i.sroa.12.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !90
  %371 = extractelement <16 x i8> %366, i64 4
  store i8 %371, ptr %_31.i.i.sroa.13.0.fresh.i.i43.sroa_idx.i, align 4, !noalias !90
  %372 = extractelement <16 x i8> %366, i64 5
  store i8 %372, ptr %_31.i.i.sroa.14.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !90
  %373 = extractelement <16 x i8> %366, i64 6
  store i8 %373, ptr %_31.i.i.sroa.15.0.fresh.i.i43.sroa_idx.i, align 2, !noalias !90
  %374 = extractelement <16 x i8> %366, i64 7
  store i8 %374, ptr %_31.i.i.sroa.16.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !90
  %375 = extractelement <16 x i8> %366, i64 8
  store i8 %375, ptr %_31.i.i.sroa.17.0.fresh.i.i43.sroa_idx.i, align 8, !noalias !90
  %376 = extractelement <16 x i8> %366, i64 9
  store i8 %376, ptr %_31.i.i.sroa.18.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !90
  %377 = extractelement <16 x i8> %366, i64 10
  store i8 %377, ptr %_31.i.i.sroa.19.0.fresh.i.i43.sroa_idx.i, align 2, !noalias !90
  %378 = extractelement <16 x i8> %366, i64 11
  store i8 %378, ptr %_31.i.i.sroa.20.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !90
  %379 = extractelement <16 x i8> %366, i64 12
  store i8 %379, ptr %_31.i.i.sroa.21.0.fresh.i.i43.sroa_idx.i, align 4, !noalias !90
  %380 = extractelement <16 x i8> %366, i64 13
  store i8 %380, ptr %_31.i.i.sroa.22.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !90
  %381 = extractelement <16 x i8> %366, i64 14
  store i8 %381, ptr %_31.i.i.sroa.23.0.fresh.i.i43.sroa_idx.i, align 2, !noalias !90
  %382 = extractelement <16 x i8> %366, i64 15
  store i8 %382, ptr %_31.i.i.sroa.24.0.fresh.i.i43.sroa_idx.i, align 1, !noalias !90
  br label %bb7.i.i65.i

_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i.i: ; preds = %bb7.i.i65.i, %bb12.i19.i.i.i, %bb10.i14.i.i.i, %bb2.i.i.i, %bb11.i.i.i
  call void @llvm.lifetime.end.p0(ptr nonnull %key.i44.i), !noalias !75
  br label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv610parse_ipv6.exit.i

bb21.i.i:                                         ; preds = %bb3.i52.i
  %_24.i55.i = load i16, ptr %_42.i51.i, align 2, !noalias !75, !noundef !12
  %383 = getelementptr i8, ptr %_37.i49.i, i64 56
  %_25.i56.i = load i16, ptr %383, align 2, !noalias !75, !noundef !12
  %384 = icmp eq i16 %_25.i56.i, -19182
  %385 = icmp eq i16 %_24.i55.i, -19182
  %or.cond.i.i = or i1 %385, %384
  br i1 %or.cond.i.i, label %bb5.i67.i, label %bb10.i.i

bb5.i67.i:                                        ; preds = %bb21.i.i
  %_21.i303.i = getelementptr i8, ptr %_37.i49.i, i64 84
  %_20.i304.i = icmp samesign ugt ptr %_21.i303.i, %_39.i50.i
  br i1 %_20.i304.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv610parse_ipv6.exit.i, label %bb7.i69.i

bb10.i.i:                                         ; preds = %bb21.i.i
  %386 = tail call i16 @llvm.bswap.i16(i16 %_24.i55.i)
  %387 = tail call i16 @llvm.bswap.i16(i16 %_25.i56.i)
  br label %bb11.i57.i

bb7.i69.i:                                        ; preds = %bb5.i67.i
  %388 = getelementptr i8, ptr %_37.i49.i, i64 82
  %_11.i306.i = load i16, ptr %388, align 2, !noalias !91, !noundef !12
  %etype.i307.i = tail call i16 @llvm.bswap.i16(i16 %_11.i306.i)
  switch i16 %etype.i307.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv610parse_ipv6.exit.i [
    i16 2048, label %bb3.i.i71.i
    i16 -31011, label %bb2.i6.i.i
  ]

bb3.i.i71.i:                                      ; preds = %bb7.i69.i
  %_63.i.i.i = getelementptr inbounds nuw i8, ptr %_37.i49.i, i64 104
  %_62.i.i.i = icmp samesign ugt ptr %_63.i.i.i, %_39.i50.i
  br i1 %_62.i.i.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv610parse_ipv6.exit.i, label %bb10.i10.i.i

bb2.i6.i.i:                                       ; preds = %bb7.i69.i
  %_51.i.i.i = getelementptr inbounds nuw i8, ptr %_37.i49.i, i64 124
  %_50.i.i.i = icmp samesign ugt ptr %_51.i.i.i, %_39.i50.i
  br i1 %_50.i.i.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv610parse_ipv6.exit.i, label %bb8.i.i70.i

bb10.i10.i.i:                                     ; preds = %bb3.i.i71.i
  %_73.i.i.i = getelementptr inbounds nuw i8, ptr %_37.i49.i, i64 96
  %_0.i14 = tail call noundef ptr inttoptr (i64 1 to ptr)(ptr noundef nonnull @BLOCKLIST, ptr noundef nonnull %_73.i.i.i) #5, !noalias !95
  %_74.i.i.i = icmp eq ptr %_0.i14, null
  br i1 %_74.i.i.i, label %bb12.i11.i.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv610parse_ipv6.exit.i

bb12.i11.i.i:                                     ; preds = %bb10.i10.i.i
  %389 = getelementptr inbounds nuw i8, ptr %_37.i49.i, i64 93
  %proto.i.i.i = load i8, ptr %389, align 1, !noalias !95, !noundef !12
  %_13.i.i72.i = load i8, ptr %_21.i303.i, align 4, !noalias !95, !noundef !12
  %_12.i.i.i = shl i8 %_13.i.i72.i, 2
  %390 = and i8 %_12.i.i.i, 60
  %narrow776.i = add nuw i8 %390, 84
  %xoff.i.i.i = zext i8 %narrow776.i to i64
  %_78.i.i.i = load i32, ptr %0, align 4, !noalias !95, !noundef !12
  %_17.i.i73.i = zext i32 %_78.i.i.i to i64
  %_80.i.i.i = load i32, ptr %ctx, align 4, !noalias !95, !noundef !12
  %_18.i.i.i = zext i32 %_80.i.i.i to i64
  %_16.i12.i.i = sub nsw i64 %_17.i.i73.i, %_18.i.i.i
  %_19.i.i.i = load i32, ptr %_73.i.i.i, align 4, !noalias !95, !noundef !12
  %391 = getelementptr inbounds nuw i8, ptr %_37.i49.i, i64 100
  %_20.i13.i.i = load i32, ptr %391, align 4, !noalias !95, !noundef !12
  switch i8 %proto.i.i.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv610parse_ipv6.exit.i [
    i8 6, label %bb4.i625.i
    i8 17, label %bb5.i533.i
  ]

bb4.i625.i:                                       ; preds = %bb12.i11.i.i
  %_31.i629.i = inttoptr i64 %_18.i.i.i to ptr
  %_33.i632.i = inttoptr i64 %_17.i.i73.i to ptr
  %_36.i633.i = getelementptr inbounds nuw i8, ptr %_31.i629.i, i64 %xoff.i.i.i
  %_38.i634.i = getelementptr inbounds nuw i8, ptr %_36.i633.i, i64 20
  %_37.i635.i = icmp samesign ugt ptr %_38.i634.i, %_33.i632.i
  br i1 %_37.i635.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv610parse_ipv6.exit.i, label %bb11.i636.i

bb5.i533.i:                                       ; preds = %bb12.i11.i.i
  %_43.i537.i = inttoptr i64 %_18.i.i.i to ptr
  %_45.i540.i = inttoptr i64 %_17.i.i73.i to ptr
  %_48.i541.i = getelementptr inbounds nuw i8, ptr %_43.i537.i, i64 %xoff.i.i.i
  %_50.i542.i = getelementptr inbounds nuw i8, ptr %_48.i541.i, i64 8
  %_49.i543.i = icmp samesign ugt ptr %_50.i542.i, %_45.i540.i
  br i1 %_49.i543.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv610parse_ipv6.exit.i, label %bb13.i544.i

bb11.i636.i:                                      ; preds = %bb4.i625.i
  %392 = getelementptr inbounds nuw i8, ptr %_36.i633.i, i64 12
  %_14.i637.i = load i8, ptr %392, align 4, !noalias !98, !noundef !12
  %393 = lshr i8 %_14.i637.i, 2
  %394 = and i8 %393, 60
  %thlen.i638.i = zext nneg i8 %394 to i64
  %_15.i639.i = load i16, ptr %_36.i633.i, align 4, !noalias !98, !noundef !12
  %395 = tail call i16 @llvm.bswap.i16(i16 %_15.i639.i)
  %396 = getelementptr inbounds nuw i8, ptr %_36.i633.i, i64 2
  %_16.i640.i = load i16, ptr %396, align 2, !noalias !98, !noundef !12
  %397 = tail call i16 @llvm.bswap.i16(i16 %_16.i640.i)
  %398 = getelementptr inbounds nuw i8, ptr %_36.i633.i, i64 13
  %399 = load i8, ptr %398, align 1, !noalias !98, !noundef !12
  br label %bb6.i547.i

bb6.i547.i:                                       ; preds = %bb13.i544.i, %bb11.i636.i
  %flags.sroa.0.0.i548.i = phi i8 [ %399, %bb11.i636.i ], [ 0, %bb13.i544.i ]
  %sp.sroa.0.0.i549.i = phi i16 [ %395, %bb11.i636.i ], [ %475, %bb13.i544.i ]
  %dp.sroa.0.0.i550.i = phi i16 [ %397, %bb11.i636.i ], [ %477, %bb13.i544.i ]
  %thlen.pn.i551.i = phi i64 [ %thlen.i638.i, %bb11.i636.i ], [ 8, %bb13.i544.i ]
  %payload_off.sroa.0.0.i552.i = add nuw nsw i64 %thlen.pn.i551.i, %xoff.i.i.i
  call void @llvm.lifetime.start.p0(ptr nonnull %key.i532.i), !noalias !98
  store i32 %_19.i.i.i, ptr %key.i532.i, align 4, !noalias !98
  %400 = getelementptr inbounds nuw i8, ptr %key.i532.i, i64 4
  store i32 %_20.i13.i.i, ptr %400, align 4, !noalias !98
  %401 = getelementptr inbounds nuw i8, ptr %key.i532.i, i64 8
  store i16 %sp.sroa.0.0.i549.i, ptr %401, align 4, !noalias !98
  %402 = getelementptr inbounds nuw i8, ptr %key.i532.i, i64 10
  store i16 %dp.sroa.0.0.i550.i, ptr %402, align 2, !noalias !98
  %403 = getelementptr inbounds nuw i8, ptr %key.i532.i, i64 12
  store i8 %proto.i.i.i, ptr %403, align 4, !noalias !98
  %404 = getelementptr inbounds nuw i8, ptr %key.i532.i, i64 13
  store i8 0, ptr %404, align 1, !noalias !98
  %_28.sroa.4.0..sroa_idx.i553.i = getelementptr inbounds nuw i8, ptr %key.i532.i, i64 14
  store i8 0, ptr %_28.sroa.4.0..sroa_idx.i553.i, align 2, !noalias !98
  %_28.sroa.5.0..sroa_idx.i554.i = getelementptr inbounds nuw i8, ptr %key.i532.i, i64 15
  store i8 0, ptr %_28.sroa.5.0..sroa_idx.i554.i, align 1, !noalias !98
  %_0.i15 = call noundef ptr inttoptr (i64 1 to ptr)(ptr noundef nonnull @FLOW_METRICS, ptr noundef nonnull readonly align 4 dereferenceable(16) %key.i532.i) #5, !noalias !101
  %_20.i.i556.i = icmp eq ptr %_0.i15, null
  br i1 %_20.i.i556.i, label %bb10.i.i589.i, label %bb11.i.i557.i

bb11.i.i557.i:                                    ; preds = %bb6.i547.i
  %405 = getelementptr inbounds nuw i8, ptr %_0.i15, i64 8
  %406 = load <2 x i64>, ptr %_0.i15, align 8, !noalias !101
  %407 = insertelement <2 x i64> <i64 poison, i64 1>, i64 %_16.i12.i.i, i64 0
  %408 = add <2 x i64> %406, %407
  %409 = extractelement <2 x i64> %408, i64 0
  store i64 %409, ptr %_0.i15, align 8, !noalias !101
  %410 = extractelement <2 x i64> %408, i64 1
  store i64 %410, ptr %405, align 8, !noalias !101
  %411 = getelementptr inbounds nuw i8, ptr %_0.i15, i64 16
  %412 = load i8, ptr %411, align 8, !noalias !101, !noundef !12
  %413 = or i8 %412, %flags.sroa.0.0.i548.i
  store i8 %413, ptr %411, align 8, !noalias !101
  %414 = icmp eq i8 %proto.i.i.i, 6
  %415 = icmp eq i16 %dp.sroa.0.0.i550.i, 443
  %or.cond.i.i558.i = and i1 %414, %415
  br i1 %or.cond.i.i558.i, label %bb2.i.i562.i, label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i559.i

bb10.i.i589.i:                                    ; preds = %bb6.i547.i
  call void @llvm.lifetime.start.p0(ptr nonnull %fresh.i.i531.i), !noalias !104
  store i64 %_16.i12.i.i, ptr %fresh.i.i531.i, align 8, !noalias !104
  %_31.i.i529.sroa.4.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 8
  store i64 1, ptr %_31.i.i529.sroa.4.0.fresh.i.i531.sroa_idx.i, align 8, !noalias !104
  %_31.i.i529.sroa.5.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 16
  store i8 %flags.sroa.0.0.i548.i, ptr %_31.i.i529.sroa.5.0.fresh.i.i531.sroa_idx.i, align 8, !noalias !104
  %_31.i.i529.sroa.6.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 17
  store i8 0, ptr %_31.i.i529.sroa.6.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !104
  %_31.i.i529.sroa.7.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 18
  store i16 0, ptr %_31.i.i529.sroa.7.0.fresh.i.i531.sroa_idx.i, align 2, !noalias !104
  %_31.i.i529.sroa.8.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 20
  store i32 0, ptr %_31.i.i529.sroa.8.0.fresh.i.i531.sroa_idx.i, align 4, !noalias !104
  %_31.i.i529.sroa.9.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 24
  store i8 0, ptr %_31.i.i529.sroa.9.0.fresh.i.i531.sroa_idx.i, align 8, !noalias !104
  %_31.i.i529.sroa.10.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 25
  store i8 0, ptr %_31.i.i529.sroa.10.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !104
  %_31.i.i529.sroa.11.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 26
  store i8 0, ptr %_31.i.i529.sroa.11.0.fresh.i.i531.sroa_idx.i, align 2, !noalias !104
  %_31.i.i529.sroa.12.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 27
  store i8 0, ptr %_31.i.i529.sroa.12.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !104
  %_31.i.i529.sroa.13.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 28
  store i8 0, ptr %_31.i.i529.sroa.13.0.fresh.i.i531.sroa_idx.i, align 4, !noalias !104
  %_31.i.i529.sroa.14.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 29
  store i8 0, ptr %_31.i.i529.sroa.14.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !104
  %_31.i.i529.sroa.15.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 30
  store i8 0, ptr %_31.i.i529.sroa.15.0.fresh.i.i531.sroa_idx.i, align 2, !noalias !104
  %_31.i.i529.sroa.16.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 31
  store i8 0, ptr %_31.i.i529.sroa.16.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !104
  %_31.i.i529.sroa.17.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 32
  store i8 0, ptr %_31.i.i529.sroa.17.0.fresh.i.i531.sroa_idx.i, align 8, !noalias !104
  %_31.i.i529.sroa.18.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 33
  store i8 0, ptr %_31.i.i529.sroa.18.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !104
  %_31.i.i529.sroa.19.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 34
  store i8 0, ptr %_31.i.i529.sroa.19.0.fresh.i.i531.sroa_idx.i, align 2, !noalias !104
  %_31.i.i529.sroa.20.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 35
  store i8 0, ptr %_31.i.i529.sroa.20.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !104
  %_31.i.i529.sroa.21.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 36
  store i8 0, ptr %_31.i.i529.sroa.21.0.fresh.i.i531.sroa_idx.i, align 4, !noalias !104
  %_31.i.i529.sroa.22.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 37
  store i8 0, ptr %_31.i.i529.sroa.22.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !104
  %_31.i.i529.sroa.23.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 38
  store i8 0, ptr %_31.i.i529.sroa.23.0.fresh.i.i531.sroa_idx.i, align 2, !noalias !104
  %_31.i.i529.sroa.24.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 39
  store i8 0, ptr %_31.i.i529.sroa.24.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !104
  %_31.i.i529.sroa.25.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 40
  store i8 0, ptr %_31.i.i529.sroa.25.0.fresh.i.i531.sroa_idx.i, align 8, !noalias !104
  %_31.i.i529.sroa.26.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 41
  store i8 0, ptr %_31.i.i529.sroa.26.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !104
  %_31.i.i529.sroa.27.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 42
  store i8 0, ptr %_31.i.i529.sroa.27.0.fresh.i.i531.sroa_idx.i, align 2, !noalias !104
  %_31.i.i529.sroa.28.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 43
  store i8 0, ptr %_31.i.i529.sroa.28.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !104
  %_31.i.i529.sroa.29.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 44
  store i8 0, ptr %_31.i.i529.sroa.29.0.fresh.i.i531.sroa_idx.i, align 4, !noalias !104
  %_31.i.i529.sroa.30.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 45
  store i8 0, ptr %_31.i.i529.sroa.30.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !104
  %_31.i.i529.sroa.31.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 46
  store i8 0, ptr %_31.i.i529.sroa.31.0.fresh.i.i531.sroa_idx.i, align 2, !noalias !104
  %_31.i.i529.sroa.32.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 47
  store i8 0, ptr %_31.i.i529.sroa.32.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !104
  %_31.i.i529.sroa.33.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 48
  store i8 0, ptr %_31.i.i529.sroa.33.0.fresh.i.i531.sroa_idx.i, align 8, !noalias !104
  %_31.i.i529.sroa.34.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 49
  store i8 0, ptr %_31.i.i529.sroa.34.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !104
  %_31.i.i529.sroa.35.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 50
  store i8 0, ptr %_31.i.i529.sroa.35.0.fresh.i.i531.sroa_idx.i, align 2, !noalias !104
  %_31.i.i529.sroa.36.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 51
  store i8 0, ptr %_31.i.i529.sroa.36.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !104
  %_31.i.i529.sroa.37.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 52
  store i8 0, ptr %_31.i.i529.sroa.37.0.fresh.i.i531.sroa_idx.i, align 4, !noalias !104
  %_31.i.i529.sroa.38.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 53
  store i8 0, ptr %_31.i.i529.sroa.38.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !104
  %_31.i.i529.sroa.39.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 54
  store i8 0, ptr %_31.i.i529.sroa.39.0.fresh.i.i531.sroa_idx.i, align 2, !noalias !104
  %_31.i.i529.sroa.40.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 55
  store i8 0, ptr %_31.i.i529.sroa.40.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !104
  %_31.i.i529.sroa.41.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 56
  store i8 0, ptr %_31.i.i529.sroa.41.0.fresh.i.i531.sroa_idx.i, align 8, !noalias !104
  %_31.i.i529.sroa.42.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 57
  store i8 0, ptr %_31.i.i529.sroa.42.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !104
  %_31.i.i529.sroa.43.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 58
  store i8 0, ptr %_31.i.i529.sroa.43.0.fresh.i.i531.sroa_idx.i, align 2, !noalias !104
  %_31.i.i529.sroa.44.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 59
  store i8 0, ptr %_31.i.i529.sroa.44.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !104
  %_31.i.i529.sroa.45.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 60
  store i8 0, ptr %_31.i.i529.sroa.45.0.fresh.i.i531.sroa_idx.i, align 4, !noalias !104
  %_31.i.i529.sroa.46.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 61
  store i8 0, ptr %_31.i.i529.sroa.46.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !104
  %_31.i.i529.sroa.47.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 62
  store i8 0, ptr %_31.i.i529.sroa.47.0.fresh.i.i531.sroa_idx.i, align 2, !noalias !104
  %_31.i.i529.sroa.48.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 63
  store i8 0, ptr %_31.i.i529.sroa.48.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !104
  %_31.i.i529.sroa.49.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 64
  store i8 0, ptr %_31.i.i529.sroa.49.0.fresh.i.i531.sroa_idx.i, align 8, !noalias !104
  %_31.i.i529.sroa.50.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 65
  store i8 0, ptr %_31.i.i529.sroa.50.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !104
  %_31.i.i529.sroa.51.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 66
  store i8 0, ptr %_31.i.i529.sroa.51.0.fresh.i.i531.sroa_idx.i, align 2, !noalias !104
  %_31.i.i529.sroa.52.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 67
  store i8 0, ptr %_31.i.i529.sroa.52.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !104
  %_31.i.i529.sroa.53.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 68
  store i8 0, ptr %_31.i.i529.sroa.53.0.fresh.i.i531.sroa_idx.i, align 4, !noalias !104
  %_31.i.i529.sroa.54.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 69
  store i8 0, ptr %_31.i.i529.sroa.54.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !104
  %_31.i.i529.sroa.55.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 70
  store i8 0, ptr %_31.i.i529.sroa.55.0.fresh.i.i531.sroa_idx.i, align 2, !noalias !104
  %_31.i.i529.sroa.56.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 71
  store i8 0, ptr %_31.i.i529.sroa.56.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !104
  %_31.i.i529.sroa.57.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 72
  store i8 0, ptr %_31.i.i529.sroa.57.0.fresh.i.i531.sroa_idx.i, align 8, !noalias !104
  %_31.i.i529.sroa.58.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 73
  store i8 0, ptr %_31.i.i529.sroa.58.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !104
  %_31.i.i529.sroa.59.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 74
  store i8 0, ptr %_31.i.i529.sroa.59.0.fresh.i.i531.sroa_idx.i, align 2, !noalias !104
  %_31.i.i529.sroa.60.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 75
  store i8 0, ptr %_31.i.i529.sroa.60.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !104
  %_31.i.i529.sroa.61.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 76
  store i8 0, ptr %_31.i.i529.sroa.61.0.fresh.i.i531.sroa_idx.i, align 4, !noalias !104
  %_31.i.i529.sroa.62.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 77
  store i8 0, ptr %_31.i.i529.sroa.62.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !104
  %_31.i.i529.sroa.63.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 78
  store i8 0, ptr %_31.i.i529.sroa.63.0.fresh.i.i531.sroa_idx.i, align 2, !noalias !104
  %_31.i.i529.sroa.64.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 79
  store i8 0, ptr %_31.i.i529.sroa.64.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !104
  %_31.i.i529.sroa.65.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 80
  store i8 0, ptr %_31.i.i529.sroa.65.0.fresh.i.i531.sroa_idx.i, align 8, !noalias !104
  %_31.i.i529.sroa.66.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 81
  store i8 0, ptr %_31.i.i529.sroa.66.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !104
  %_31.i.i529.sroa.67.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 82
  store i8 0, ptr %_31.i.i529.sroa.67.0.fresh.i.i531.sroa_idx.i, align 2, !noalias !104
  %_31.i.i529.sroa.68.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 83
  store i8 0, ptr %_31.i.i529.sroa.68.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !104
  %_31.i.i529.sroa.69.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 84
  store i8 0, ptr %_31.i.i529.sroa.69.0.fresh.i.i531.sroa_idx.i, align 4, !noalias !104
  %_31.i.i529.sroa.70.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 85
  store i8 0, ptr %_31.i.i529.sroa.70.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !104
  %_31.i.i529.sroa.71.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 86
  store i8 0, ptr %_31.i.i529.sroa.71.0.fresh.i.i531.sroa_idx.i, align 2, !noalias !104
  %_31.i.i529.sroa.72.0.fresh.i.i531.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i531.i, i64 87
  store i8 0, ptr %_31.i.i529.sroa.72.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !104
  %416 = icmp eq i8 %proto.i.i.i, 6
  %417 = icmp eq i16 %dp.sroa.0.0.i550.i, 443
  %or.cond1.i.i594.i = and i1 %416, %417
  br i1 %or.cond1.i.i594.i, label %bb5.i.i597.i, label %bb7.i.i595.i

bb2.i.i562.i:                                     ; preds = %bb11.i.i557.i
  %_28.i5.i.i564.i = load i32, ptr %ctx, align 4, !noalias !106, !noundef !12
  %_22.i6.i.i565.i = zext i32 %_28.i5.i.i564.i to i64
  %_21.i7.i.i566.i = inttoptr i64 %_22.i6.i.i565.i to ptr
  %_30.i8.i.i567.i = load i32, ptr %0, align 4, !noalias !106, !noundef !12
  %_24.i9.i.i568.i = zext i32 %_30.i8.i.i567.i to i64
  %_23.i10.i.i569.i = inttoptr i64 %_24.i9.i.i568.i to ptr
  %_25.i11.i.i570.i = getelementptr inbounds nuw i8, ptr %_21.i7.i.i566.i, i64 %payload_off.sroa.0.0.i552.i
  %_27.i12.i.i571.i = getelementptr inbounds nuw i8, ptr %_25.i11.i.i570.i, i64 1
  %_26.i13.i.i572.i = icmp samesign ugt ptr %_27.i12.i.i571.i, %_23.i10.i.i569.i
  br i1 %_26.i13.i.i572.i, label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i559.i, label %bb10.i14.i.i573.i

bb10.i14.i.i573.i:                                ; preds = %bb2.i.i562.i
  %_6.i15.i.i574.i = load i8, ptr %_25.i11.i.i570.i, align 1, !noalias !106, !noundef !12
  %418 = icmp ne i8 %_6.i15.i.i574.i, 22
  %_39.i17.i.i577.i = getelementptr i8, ptr %_25.i11.i.i570.i, i64 21
  %_38.i18.i.i578.i = icmp samesign ugt ptr %_39.i17.i.i577.i, %_23.i10.i.i569.i
  %or.cond772.i = or i1 %_38.i18.i.i578.i, %418
  br i1 %or.cond772.i, label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i559.i, label %bb12.i19.i.i579.i

bb12.i19.i.i579.i:                                ; preds = %bb10.i14.i.i573.i
  %_37.i20.i.i580.i = getelementptr i8, ptr %_25.i11.i.i570.i, i64 5
  %_13.i21.i.i581.i = getelementptr inbounds nuw i8, ptr %_0.i15, i64 24
  call void @llvm.memcpy.p0.p0.i64(ptr noundef nonnull align 1 dereferenceable(16) %_13.i21.i.i581.i, ptr noundef nonnull align 1 dereferenceable(16) %_37.i20.i.i580.i, i64 16, i1 false), !noalias !106
  %419 = getelementptr inbounds nuw i8, ptr %_0.i15, i64 25
  %420 = getelementptr inbounds nuw i8, ptr %_0.i15, i64 26
  %421 = getelementptr inbounds nuw i8, ptr %_0.i15, i64 27
  %422 = getelementptr inbounds nuw i8, ptr %_0.i15, i64 28
  %423 = getelementptr inbounds nuw i8, ptr %_0.i15, i64 29
  %424 = getelementptr inbounds nuw i8, ptr %_0.i15, i64 30
  %425 = getelementptr inbounds nuw i8, ptr %_0.i15, i64 31
  %426 = getelementptr inbounds nuw i8, ptr %_0.i15, i64 32
  %427 = getelementptr inbounds nuw i8, ptr %_0.i15, i64 33
  %428 = getelementptr inbounds nuw i8, ptr %_0.i15, i64 34
  %429 = getelementptr inbounds nuw i8, ptr %_0.i15, i64 35
  %430 = getelementptr inbounds nuw i8, ptr %_0.i15, i64 36
  %431 = getelementptr inbounds nuw i8, ptr %_0.i15, i64 37
  %432 = getelementptr inbounds nuw i8, ptr %_0.i15, i64 38
  %433 = getelementptr inbounds nuw i8, ptr %_0.i15, i64 39
  %434 = load <16 x i8>, ptr %_13.i21.i.i581.i, align 8, !noalias !106
  %435 = add <16 x i8> %434, splat (i8 -32)
  %436 = icmp ult <16 x i8> %435, splat (i8 95)
  %437 = select <16 x i1> %436, <16 x i8> %434, <16 x i8> zeroinitializer
  %438 = extractelement <16 x i8> %437, i64 0
  store i8 %438, ptr %_13.i21.i.i581.i, align 8, !noalias !106
  %439 = extractelement <16 x i8> %437, i64 1
  store i8 %439, ptr %419, align 1, !noalias !106
  %440 = extractelement <16 x i8> %437, i64 2
  store i8 %440, ptr %420, align 2, !noalias !106
  %441 = extractelement <16 x i8> %437, i64 3
  store i8 %441, ptr %421, align 1, !noalias !106
  %442 = extractelement <16 x i8> %437, i64 4
  store i8 %442, ptr %422, align 4, !noalias !106
  %443 = extractelement <16 x i8> %437, i64 5
  store i8 %443, ptr %423, align 1, !noalias !106
  %444 = extractelement <16 x i8> %437, i64 6
  store i8 %444, ptr %424, align 2, !noalias !106
  %445 = extractelement <16 x i8> %437, i64 7
  store i8 %445, ptr %425, align 1, !noalias !106
  %446 = extractelement <16 x i8> %437, i64 8
  store i8 %446, ptr %426, align 8, !noalias !106
  %447 = extractelement <16 x i8> %437, i64 9
  store i8 %447, ptr %427, align 1, !noalias !106
  %448 = extractelement <16 x i8> %437, i64 10
  store i8 %448, ptr %428, align 2, !noalias !106
  %449 = extractelement <16 x i8> %437, i64 11
  store i8 %449, ptr %429, align 1, !noalias !106
  %450 = extractelement <16 x i8> %437, i64 12
  store i8 %450, ptr %430, align 4, !noalias !106
  %451 = extractelement <16 x i8> %437, i64 13
  store i8 %451, ptr %431, align 1, !noalias !106
  %452 = extractelement <16 x i8> %437, i64 14
  store i8 %452, ptr %432, align 2, !noalias !106
  %453 = extractelement <16 x i8> %437, i64 15
  store i8 %453, ptr %433, align 1, !noalias !106
  br label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i559.i

bb7.i.i595.i:                                     ; preds = %bb12.i.i.i614.i, %bb10.i.i.i608.i, %bb5.i.i597.i, %bb10.i.i589.i
  %_0.i16 = call noundef i64 inttoptr (i64 2 to ptr)(ptr noundef nonnull @FLOW_METRICS, ptr noundef nonnull readonly align 4 dereferenceable(16) %key.i532.i, ptr noundef nonnull %fresh.i.i531.i, i64 noundef 0) #5
  call void @llvm.lifetime.end.p0(ptr nonnull %fresh.i.i531.i), !noalias !104
  br label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i559.i

bb5.i.i597.i:                                     ; preds = %bb10.i.i589.i
  %_28.i.i.i599.i = load i32, ptr %ctx, align 4, !noalias !109, !noundef !12
  %_22.i.i.i600.i = zext i32 %_28.i.i.i599.i to i64
  %_21.i.i.i601.i = inttoptr i64 %_22.i.i.i600.i to ptr
  %_30.i.i.i602.i = load i32, ptr %0, align 4, !noalias !109, !noundef !12
  %_24.i.i.i603.i = zext i32 %_30.i.i.i602.i to i64
  %_23.i.i.i604.i = inttoptr i64 %_24.i.i.i603.i to ptr
  %_25.i.i.i605.i = getelementptr inbounds nuw i8, ptr %_21.i.i.i601.i, i64 %payload_off.sroa.0.0.i552.i
  %_27.i.i.i606.i = getelementptr inbounds nuw i8, ptr %_25.i.i.i605.i, i64 1
  %_26.i.i.i607.i = icmp samesign ugt ptr %_27.i.i.i606.i, %_23.i.i.i604.i
  br i1 %_26.i.i.i607.i, label %bb7.i.i595.i, label %bb10.i.i.i608.i

bb10.i.i.i608.i:                                  ; preds = %bb5.i.i597.i
  %_6.i.i.i609.i = load i8, ptr %_25.i.i.i605.i, align 1, !noalias !109, !noundef !12
  %454 = icmp ne i8 %_6.i.i.i609.i, 22
  %_39.i.i.i612.i = getelementptr i8, ptr %_25.i.i.i605.i, i64 21
  %_38.i.i.i613.i = icmp samesign ugt ptr %_39.i.i.i612.i, %_23.i.i.i604.i
  %or.cond773.i = or i1 %_38.i.i.i613.i, %454
  br i1 %or.cond773.i, label %bb7.i.i595.i, label %bb12.i.i.i614.i

bb12.i.i.i614.i:                                  ; preds = %bb10.i.i.i608.i
  %_37.i.i.i615.i = getelementptr i8, ptr %_25.i.i.i605.i, i64 5
  call void @llvm.memcpy.p0.p0.i64(ptr noundef nonnull align 8 dereferenceable(16) %_31.i.i529.sroa.9.0.fresh.i.i531.sroa_idx.i, ptr noundef nonnull align 1 dereferenceable(16) %_37.i.i.i615.i, i64 16, i1 false), !noalias !109
  %455 = load <16 x i8>, ptr %_31.i.i529.sroa.9.0.fresh.i.i531.sroa_idx.i, align 8, !noalias !112
  %456 = add <16 x i8> %455, splat (i8 -32)
  %457 = icmp ult <16 x i8> %456, splat (i8 95)
  %458 = select <16 x i1> %457, <16 x i8> %455, <16 x i8> zeroinitializer
  %459 = extractelement <16 x i8> %458, i64 0
  store i8 %459, ptr %_31.i.i529.sroa.9.0.fresh.i.i531.sroa_idx.i, align 8, !noalias !112
  %460 = extractelement <16 x i8> %458, i64 1
  store i8 %460, ptr %_31.i.i529.sroa.10.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !112
  %461 = extractelement <16 x i8> %458, i64 2
  store i8 %461, ptr %_31.i.i529.sroa.11.0.fresh.i.i531.sroa_idx.i, align 2, !noalias !112
  %462 = extractelement <16 x i8> %458, i64 3
  store i8 %462, ptr %_31.i.i529.sroa.12.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !112
  %463 = extractelement <16 x i8> %458, i64 4
  store i8 %463, ptr %_31.i.i529.sroa.13.0.fresh.i.i531.sroa_idx.i, align 4, !noalias !112
  %464 = extractelement <16 x i8> %458, i64 5
  store i8 %464, ptr %_31.i.i529.sroa.14.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !112
  %465 = extractelement <16 x i8> %458, i64 6
  store i8 %465, ptr %_31.i.i529.sroa.15.0.fresh.i.i531.sroa_idx.i, align 2, !noalias !112
  %466 = extractelement <16 x i8> %458, i64 7
  store i8 %466, ptr %_31.i.i529.sroa.16.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !112
  %467 = extractelement <16 x i8> %458, i64 8
  store i8 %467, ptr %_31.i.i529.sroa.17.0.fresh.i.i531.sroa_idx.i, align 8, !noalias !112
  %468 = extractelement <16 x i8> %458, i64 9
  store i8 %468, ptr %_31.i.i529.sroa.18.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !112
  %469 = extractelement <16 x i8> %458, i64 10
  store i8 %469, ptr %_31.i.i529.sroa.19.0.fresh.i.i531.sroa_idx.i, align 2, !noalias !112
  %470 = extractelement <16 x i8> %458, i64 11
  store i8 %470, ptr %_31.i.i529.sroa.20.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !112
  %471 = extractelement <16 x i8> %458, i64 12
  store i8 %471, ptr %_31.i.i529.sroa.21.0.fresh.i.i531.sroa_idx.i, align 4, !noalias !112
  %472 = extractelement <16 x i8> %458, i64 13
  store i8 %472, ptr %_31.i.i529.sroa.22.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !112
  %473 = extractelement <16 x i8> %458, i64 14
  store i8 %473, ptr %_31.i.i529.sroa.23.0.fresh.i.i531.sroa_idx.i, align 2, !noalias !112
  %474 = extractelement <16 x i8> %458, i64 15
  store i8 %474, ptr %_31.i.i529.sroa.24.0.fresh.i.i531.sroa_idx.i, align 1, !noalias !112
  br label %bb7.i.i595.i

_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i559.i: ; preds = %bb7.i.i595.i, %bb12.i19.i.i579.i, %bb10.i14.i.i573.i, %bb2.i.i562.i, %bb11.i.i557.i
  call void @llvm.lifetime.end.p0(ptr nonnull %key.i532.i), !noalias !98
  br label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv610parse_ipv6.exit.i

bb13.i544.i:                                      ; preds = %bb5.i533.i
  %_23.i545.i = load i16, ptr %_48.i541.i, align 2, !noalias !98, !noundef !12
  %475 = tail call i16 @llvm.bswap.i16(i16 %_23.i545.i)
  %476 = getelementptr inbounds nuw i8, ptr %_48.i541.i, i64 2
  %_25.i546.i = load i16, ptr %476, align 2, !noalias !98, !noundef !12
  %477 = tail call i16 @llvm.bswap.i16(i16 %_25.i546.i)
  br label %bb6.i547.i

bb8.i.i70.i:                                      ; preds = %bb2.i6.i.i
  %_87.i.i.i = getelementptr inbounds nuw i8, ptr %_37.i49.i, i64 92
  %_0.i17 = tail call noundef ptr inttoptr (i64 1 to ptr)(ptr noundef nonnull @BLOCKLIST_V6, ptr noundef nonnull %_87.i.i.i) #5, !noalias !95
  %_88.i.i.i = icmp eq ptr %_0.i17, null
  br i1 %_88.i.i.i, label %bb15.i7.i.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv610parse_ipv6.exit.i

bb15.i7.i.i:                                      ; preds = %bb8.i.i70.i
  %478 = getelementptr inbounds nuw i8, ptr %_37.i49.i, i64 90
  %proto1.i.i.i = load i8, ptr %478, align 2, !noalias !95, !noundef !12
  %_92.i.i.i = load i32, ptr %0, align 4, !noalias !95, !noundef !12
  %_30.i.i.i = zext i32 %_92.i.i.i to i64
  %_94.i.i.i = load i32, ptr %ctx, align 4, !noalias !95, !noundef !12
  %_31.i8.i.i = zext i32 %_94.i.i.i to i64
  %_29.i.i.i = sub nsw i64 %_30.i.i.i, %_31.i8.i.i
  %479 = getelementptr inbounds nuw i8, ptr %_37.i49.i, i64 104
  %_34.i9.i.i = load i8, ptr %479, align 4, !noalias !95, !noundef !12
  %480 = getelementptr inbounds nuw i8, ptr %_37.i49.i, i64 105
  %_35.i.i.i = load i8, ptr %480, align 1, !noalias !95, !noundef !12
  %481 = getelementptr inbounds nuw i8, ptr %_37.i49.i, i64 106
  %_36.i.i.i = load i8, ptr %481, align 2, !noalias !95, !noundef !12
  %482 = getelementptr inbounds nuw i8, ptr %_37.i49.i, i64 107
  %_37.i.i.i = load i8, ptr %482, align 1, !noalias !95, !noundef !12
  %_33.sroa.6.0.insert.ext.i.i.i = zext i8 %_37.i.i.i to i32
  %_33.sroa.6.0.insert.shift.i.i.i = shl nuw i32 %_33.sroa.6.0.insert.ext.i.i.i, 24
  %_33.sroa.5.0.insert.ext.i.i.i = zext i8 %_36.i.i.i to i32
  %_33.sroa.5.0.insert.shift.i.i.i = shl nuw nsw i32 %_33.sroa.5.0.insert.ext.i.i.i, 16
  %_33.sroa.4.0.insert.ext.i.i.i = zext i8 %_35.i.i.i to i32
  %_33.sroa.4.0.insert.shift.i.i.i = shl nuw nsw i32 %_33.sroa.4.0.insert.ext.i.i.i, 8
  %_33.sroa.0.0.insert.ext.i.i.i = zext i8 %_34.i9.i.i to i32
  %_33.sroa.5.0.insert.insert.i.i.i = or disjoint i32 %_33.sroa.4.0.insert.shift.i.i.i, %_33.sroa.0.0.insert.ext.i.i.i
  %_33.sroa.4.0.insert.insert.i.i.i = or disjoint i32 %_33.sroa.5.0.insert.insert.i.i.i, %_33.sroa.5.0.insert.shift.i.i.i
  %_33.sroa.0.0.insert.insert.i.i.i = or disjoint i32 %_33.sroa.4.0.insert.insert.i.i.i, %_33.sroa.6.0.insert.shift.i.i.i
  %src_lo.i.i.i = tail call i32 @llvm.bswap.i32(i32 %_33.sroa.0.0.insert.insert.i.i.i)
  %483 = getelementptr inbounds nuw i8, ptr %_37.i49.i, i64 120
  %_40.i.i.i = load i8, ptr %483, align 4, !noalias !95, !noundef !12
  %484 = getelementptr inbounds nuw i8, ptr %_37.i49.i, i64 121
  %_41.i.i.i = load i8, ptr %484, align 1, !noalias !95, !noundef !12
  %485 = getelementptr inbounds nuw i8, ptr %_37.i49.i, i64 122
  %_42.i.i.i = load i8, ptr %485, align 2, !noalias !95, !noundef !12
  %486 = getelementptr inbounds nuw i8, ptr %_37.i49.i, i64 123
  %_43.i.i.i = load i8, ptr %486, align 1, !noalias !95, !noundef !12
  %_39.sroa.6.0.insert.ext.i.i.i = zext i8 %_43.i.i.i to i32
  %_39.sroa.6.0.insert.shift.i.i.i = shl nuw i32 %_39.sroa.6.0.insert.ext.i.i.i, 24
  %_39.sroa.5.0.insert.ext.i.i.i = zext i8 %_42.i.i.i to i32
  %_39.sroa.5.0.insert.shift.i.i.i = shl nuw nsw i32 %_39.sroa.5.0.insert.ext.i.i.i, 16
  %_39.sroa.4.0.insert.ext.i.i.i = zext i8 %_41.i.i.i to i32
  %_39.sroa.4.0.insert.shift.i.i.i = shl nuw nsw i32 %_39.sroa.4.0.insert.ext.i.i.i, 8
  %_39.sroa.0.0.insert.ext.i.i.i = zext i8 %_40.i.i.i to i32
  %_39.sroa.5.0.insert.insert.i.i.i = or disjoint i32 %_39.sroa.4.0.insert.shift.i.i.i, %_39.sroa.0.0.insert.ext.i.i.i
  %_39.sroa.4.0.insert.insert.i.i.i = or disjoint i32 %_39.sroa.5.0.insert.insert.i.i.i, %_39.sroa.5.0.insert.shift.i.i.i
  %_39.sroa.0.0.insert.insert.i.i.i = or disjoint i32 %_39.sroa.4.0.insert.insert.i.i.i, %_39.sroa.6.0.insert.shift.i.i.i
  %dst_lo.i.i.i = tail call i32 @llvm.bswap.i32(i32 %_39.sroa.0.0.insert.insert.i.i.i)
  switch i8 %proto1.i.i.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv610parse_ipv6.exit.i [
    i8 6, label %bb4.i738.i
    i8 17, label %bb5.i646.i
  ]

bb4.i738.i:                                       ; preds = %bb15.i7.i.i
  %_31.i742.i = inttoptr i64 %_31.i8.i.i to ptr
  %_33.i745.i = inttoptr i64 %_30.i.i.i to ptr
  %_38.i747.i = getelementptr inbounds nuw i8, ptr %_31.i742.i, i64 144
  %_37.i748.i = icmp samesign ugt ptr %_38.i747.i, %_33.i745.i
  br i1 %_37.i748.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv610parse_ipv6.exit.i, label %bb11.i749.i

bb5.i646.i:                                       ; preds = %bb15.i7.i.i
  %_43.i650.i = inttoptr i64 %_31.i8.i.i to ptr
  %_45.i653.i = inttoptr i64 %_30.i.i.i to ptr
  %_50.i655.i = getelementptr inbounds nuw i8, ptr %_43.i650.i, i64 132
  %_49.i656.i = icmp samesign ugt ptr %_50.i655.i, %_45.i653.i
  br i1 %_49.i656.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv610parse_ipv6.exit.i, label %bb13.i657.i

bb11.i749.i:                                      ; preds = %bb4.i738.i
  %_36.i746.i = getelementptr inbounds nuw i8, ptr %_31.i742.i, i64 124
  %487 = getelementptr inbounds nuw i8, ptr %_31.i742.i, i64 136
  %_14.i750.i = load i8, ptr %487, align 4, !noalias !113, !noundef !12
  %488 = lshr i8 %_14.i750.i, 2
  %489 = and i8 %488, 60
  %_15.i752.i = load i16, ptr %_36.i746.i, align 4, !noalias !113, !noundef !12
  %490 = tail call i16 @llvm.bswap.i16(i16 %_15.i752.i)
  %491 = getelementptr inbounds nuw i8, ptr %_31.i742.i, i64 126
  %_16.i753.i = load i16, ptr %491, align 2, !noalias !113, !noundef !12
  %492 = tail call i16 @llvm.bswap.i16(i16 %_16.i753.i)
  %493 = getelementptr inbounds nuw i8, ptr %_31.i742.i, i64 137
  %494 = load i8, ptr %493, align 1, !noalias !113, !noundef !12
  %narrow.i = add nuw i8 %489, 124
  %495 = zext i8 %narrow.i to i64
  br label %bb6.i660.i

bb6.i660.i:                                       ; preds = %bb13.i657.i, %bb11.i749.i
  %flags.sroa.0.0.i661.i = phi i8 [ %494, %bb11.i749.i ], [ 0, %bb13.i657.i ]
  %sp.sroa.0.0.i662.i = phi i16 [ %490, %bb11.i749.i ], [ %571, %bb13.i657.i ]
  %dp.sroa.0.0.i663.i = phi i16 [ %492, %bb11.i749.i ], [ %573, %bb13.i657.i ]
  %thlen.pn.i664.i = phi i64 [ %495, %bb11.i749.i ], [ 132, %bb13.i657.i ]
  call void @llvm.lifetime.start.p0(ptr nonnull %key.i645.i), !noalias !113
  store i32 %src_lo.i.i.i, ptr %key.i645.i, align 4, !noalias !113
  %496 = getelementptr inbounds nuw i8, ptr %key.i645.i, i64 4
  store i32 %dst_lo.i.i.i, ptr %496, align 4, !noalias !113
  %497 = getelementptr inbounds nuw i8, ptr %key.i645.i, i64 8
  store i16 %sp.sroa.0.0.i662.i, ptr %497, align 4, !noalias !113
  %498 = getelementptr inbounds nuw i8, ptr %key.i645.i, i64 10
  store i16 %dp.sroa.0.0.i663.i, ptr %498, align 2, !noalias !113
  %499 = getelementptr inbounds nuw i8, ptr %key.i645.i, i64 12
  store i8 %proto1.i.i.i, ptr %499, align 4, !noalias !113
  %500 = getelementptr inbounds nuw i8, ptr %key.i645.i, i64 13
  store i8 0, ptr %500, align 1, !noalias !113
  %_28.sroa.4.0..sroa_idx.i666.i = getelementptr inbounds nuw i8, ptr %key.i645.i, i64 14
  store i8 0, ptr %_28.sroa.4.0..sroa_idx.i666.i, align 2, !noalias !113
  %_28.sroa.5.0..sroa_idx.i667.i = getelementptr inbounds nuw i8, ptr %key.i645.i, i64 15
  store i8 0, ptr %_28.sroa.5.0..sroa_idx.i667.i, align 1, !noalias !113
  %_0.i18 = call noundef ptr inttoptr (i64 1 to ptr)(ptr noundef nonnull @FLOW_METRICS, ptr noundef nonnull readonly align 4 dereferenceable(16) %key.i645.i) #5, !noalias !116
  %_20.i.i669.i = icmp eq ptr %_0.i18, null
  br i1 %_20.i.i669.i, label %bb10.i.i702.i, label %bb11.i.i670.i

bb11.i.i670.i:                                    ; preds = %bb6.i660.i
  %501 = getelementptr inbounds nuw i8, ptr %_0.i18, i64 8
  %502 = load <2 x i64>, ptr %_0.i18, align 8, !noalias !116
  %503 = insertelement <2 x i64> <i64 poison, i64 1>, i64 %_29.i.i.i, i64 0
  %504 = add <2 x i64> %502, %503
  %505 = extractelement <2 x i64> %504, i64 0
  store i64 %505, ptr %_0.i18, align 8, !noalias !116
  %506 = extractelement <2 x i64> %504, i64 1
  store i64 %506, ptr %501, align 8, !noalias !116
  %507 = getelementptr inbounds nuw i8, ptr %_0.i18, i64 16
  %508 = load i8, ptr %507, align 8, !noalias !116, !noundef !12
  %509 = or i8 %508, %flags.sroa.0.0.i661.i
  store i8 %509, ptr %507, align 8, !noalias !116
  %510 = icmp eq i8 %proto1.i.i.i, 6
  %511 = icmp eq i16 %dp.sroa.0.0.i663.i, 443
  %or.cond.i.i671.i = and i1 %510, %511
  br i1 %or.cond.i.i671.i, label %bb2.i.i675.i, label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i672.i

bb10.i.i702.i:                                    ; preds = %bb6.i660.i
  call void @llvm.lifetime.start.p0(ptr nonnull %fresh.i.i644.i), !noalias !119
  store i64 %_29.i.i.i, ptr %fresh.i.i644.i, align 8, !noalias !119
  %_31.i.i642.sroa.4.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 8
  store i64 1, ptr %_31.i.i642.sroa.4.0.fresh.i.i644.sroa_idx.i, align 8, !noalias !119
  %_31.i.i642.sroa.5.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 16
  store i8 %flags.sroa.0.0.i661.i, ptr %_31.i.i642.sroa.5.0.fresh.i.i644.sroa_idx.i, align 8, !noalias !119
  %_31.i.i642.sroa.6.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 17
  store i8 0, ptr %_31.i.i642.sroa.6.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !119
  %_31.i.i642.sroa.7.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 18
  store i16 0, ptr %_31.i.i642.sroa.7.0.fresh.i.i644.sroa_idx.i, align 2, !noalias !119
  %_31.i.i642.sroa.8.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 20
  store i32 0, ptr %_31.i.i642.sroa.8.0.fresh.i.i644.sroa_idx.i, align 4, !noalias !119
  %_31.i.i642.sroa.9.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 24
  store i8 0, ptr %_31.i.i642.sroa.9.0.fresh.i.i644.sroa_idx.i, align 8, !noalias !119
  %_31.i.i642.sroa.10.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 25
  store i8 0, ptr %_31.i.i642.sroa.10.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !119
  %_31.i.i642.sroa.11.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 26
  store i8 0, ptr %_31.i.i642.sroa.11.0.fresh.i.i644.sroa_idx.i, align 2, !noalias !119
  %_31.i.i642.sroa.12.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 27
  store i8 0, ptr %_31.i.i642.sroa.12.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !119
  %_31.i.i642.sroa.13.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 28
  store i8 0, ptr %_31.i.i642.sroa.13.0.fresh.i.i644.sroa_idx.i, align 4, !noalias !119
  %_31.i.i642.sroa.14.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 29
  store i8 0, ptr %_31.i.i642.sroa.14.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !119
  %_31.i.i642.sroa.15.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 30
  store i8 0, ptr %_31.i.i642.sroa.15.0.fresh.i.i644.sroa_idx.i, align 2, !noalias !119
  %_31.i.i642.sroa.16.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 31
  store i8 0, ptr %_31.i.i642.sroa.16.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !119
  %_31.i.i642.sroa.17.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 32
  store i8 0, ptr %_31.i.i642.sroa.17.0.fresh.i.i644.sroa_idx.i, align 8, !noalias !119
  %_31.i.i642.sroa.18.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 33
  store i8 0, ptr %_31.i.i642.sroa.18.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !119
  %_31.i.i642.sroa.19.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 34
  store i8 0, ptr %_31.i.i642.sroa.19.0.fresh.i.i644.sroa_idx.i, align 2, !noalias !119
  %_31.i.i642.sroa.20.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 35
  store i8 0, ptr %_31.i.i642.sroa.20.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !119
  %_31.i.i642.sroa.21.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 36
  store i8 0, ptr %_31.i.i642.sroa.21.0.fresh.i.i644.sroa_idx.i, align 4, !noalias !119
  %_31.i.i642.sroa.22.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 37
  store i8 0, ptr %_31.i.i642.sroa.22.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !119
  %_31.i.i642.sroa.23.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 38
  store i8 0, ptr %_31.i.i642.sroa.23.0.fresh.i.i644.sroa_idx.i, align 2, !noalias !119
  %_31.i.i642.sroa.24.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 39
  store i8 0, ptr %_31.i.i642.sroa.24.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !119
  %_31.i.i642.sroa.25.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 40
  store i8 0, ptr %_31.i.i642.sroa.25.0.fresh.i.i644.sroa_idx.i, align 8, !noalias !119
  %_31.i.i642.sroa.26.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 41
  store i8 0, ptr %_31.i.i642.sroa.26.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !119
  %_31.i.i642.sroa.27.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 42
  store i8 0, ptr %_31.i.i642.sroa.27.0.fresh.i.i644.sroa_idx.i, align 2, !noalias !119
  %_31.i.i642.sroa.28.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 43
  store i8 0, ptr %_31.i.i642.sroa.28.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !119
  %_31.i.i642.sroa.29.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 44
  store i8 0, ptr %_31.i.i642.sroa.29.0.fresh.i.i644.sroa_idx.i, align 4, !noalias !119
  %_31.i.i642.sroa.30.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 45
  store i8 0, ptr %_31.i.i642.sroa.30.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !119
  %_31.i.i642.sroa.31.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 46
  store i8 0, ptr %_31.i.i642.sroa.31.0.fresh.i.i644.sroa_idx.i, align 2, !noalias !119
  %_31.i.i642.sroa.32.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 47
  store i8 0, ptr %_31.i.i642.sroa.32.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !119
  %_31.i.i642.sroa.33.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 48
  store i8 0, ptr %_31.i.i642.sroa.33.0.fresh.i.i644.sroa_idx.i, align 8, !noalias !119
  %_31.i.i642.sroa.34.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 49
  store i8 0, ptr %_31.i.i642.sroa.34.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !119
  %_31.i.i642.sroa.35.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 50
  store i8 0, ptr %_31.i.i642.sroa.35.0.fresh.i.i644.sroa_idx.i, align 2, !noalias !119
  %_31.i.i642.sroa.36.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 51
  store i8 0, ptr %_31.i.i642.sroa.36.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !119
  %_31.i.i642.sroa.37.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 52
  store i8 0, ptr %_31.i.i642.sroa.37.0.fresh.i.i644.sroa_idx.i, align 4, !noalias !119
  %_31.i.i642.sroa.38.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 53
  store i8 0, ptr %_31.i.i642.sroa.38.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !119
  %_31.i.i642.sroa.39.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 54
  store i8 0, ptr %_31.i.i642.sroa.39.0.fresh.i.i644.sroa_idx.i, align 2, !noalias !119
  %_31.i.i642.sroa.40.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 55
  store i8 0, ptr %_31.i.i642.sroa.40.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !119
  %_31.i.i642.sroa.41.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 56
  store i8 0, ptr %_31.i.i642.sroa.41.0.fresh.i.i644.sroa_idx.i, align 8, !noalias !119
  %_31.i.i642.sroa.42.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 57
  store i8 0, ptr %_31.i.i642.sroa.42.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !119
  %_31.i.i642.sroa.43.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 58
  store i8 0, ptr %_31.i.i642.sroa.43.0.fresh.i.i644.sroa_idx.i, align 2, !noalias !119
  %_31.i.i642.sroa.44.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 59
  store i8 0, ptr %_31.i.i642.sroa.44.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !119
  %_31.i.i642.sroa.45.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 60
  store i8 0, ptr %_31.i.i642.sroa.45.0.fresh.i.i644.sroa_idx.i, align 4, !noalias !119
  %_31.i.i642.sroa.46.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 61
  store i8 0, ptr %_31.i.i642.sroa.46.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !119
  %_31.i.i642.sroa.47.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 62
  store i8 0, ptr %_31.i.i642.sroa.47.0.fresh.i.i644.sroa_idx.i, align 2, !noalias !119
  %_31.i.i642.sroa.48.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 63
  store i8 0, ptr %_31.i.i642.sroa.48.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !119
  %_31.i.i642.sroa.49.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 64
  store i8 0, ptr %_31.i.i642.sroa.49.0.fresh.i.i644.sroa_idx.i, align 8, !noalias !119
  %_31.i.i642.sroa.50.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 65
  store i8 0, ptr %_31.i.i642.sroa.50.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !119
  %_31.i.i642.sroa.51.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 66
  store i8 0, ptr %_31.i.i642.sroa.51.0.fresh.i.i644.sroa_idx.i, align 2, !noalias !119
  %_31.i.i642.sroa.52.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 67
  store i8 0, ptr %_31.i.i642.sroa.52.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !119
  %_31.i.i642.sroa.53.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 68
  store i8 0, ptr %_31.i.i642.sroa.53.0.fresh.i.i644.sroa_idx.i, align 4, !noalias !119
  %_31.i.i642.sroa.54.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 69
  store i8 0, ptr %_31.i.i642.sroa.54.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !119
  %_31.i.i642.sroa.55.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 70
  store i8 0, ptr %_31.i.i642.sroa.55.0.fresh.i.i644.sroa_idx.i, align 2, !noalias !119
  %_31.i.i642.sroa.56.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 71
  store i8 0, ptr %_31.i.i642.sroa.56.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !119
  %_31.i.i642.sroa.57.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 72
  store i8 0, ptr %_31.i.i642.sroa.57.0.fresh.i.i644.sroa_idx.i, align 8, !noalias !119
  %_31.i.i642.sroa.58.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 73
  store i8 0, ptr %_31.i.i642.sroa.58.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !119
  %_31.i.i642.sroa.59.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 74
  store i8 0, ptr %_31.i.i642.sroa.59.0.fresh.i.i644.sroa_idx.i, align 2, !noalias !119
  %_31.i.i642.sroa.60.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 75
  store i8 0, ptr %_31.i.i642.sroa.60.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !119
  %_31.i.i642.sroa.61.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 76
  store i8 0, ptr %_31.i.i642.sroa.61.0.fresh.i.i644.sroa_idx.i, align 4, !noalias !119
  %_31.i.i642.sroa.62.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 77
  store i8 0, ptr %_31.i.i642.sroa.62.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !119
  %_31.i.i642.sroa.63.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 78
  store i8 0, ptr %_31.i.i642.sroa.63.0.fresh.i.i644.sroa_idx.i, align 2, !noalias !119
  %_31.i.i642.sroa.64.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 79
  store i8 0, ptr %_31.i.i642.sroa.64.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !119
  %_31.i.i642.sroa.65.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 80
  store i8 0, ptr %_31.i.i642.sroa.65.0.fresh.i.i644.sroa_idx.i, align 8, !noalias !119
  %_31.i.i642.sroa.66.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 81
  store i8 0, ptr %_31.i.i642.sroa.66.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !119
  %_31.i.i642.sroa.67.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 82
  store i8 0, ptr %_31.i.i642.sroa.67.0.fresh.i.i644.sroa_idx.i, align 2, !noalias !119
  %_31.i.i642.sroa.68.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 83
  store i8 0, ptr %_31.i.i642.sroa.68.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !119
  %_31.i.i642.sroa.69.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 84
  store i8 0, ptr %_31.i.i642.sroa.69.0.fresh.i.i644.sroa_idx.i, align 4, !noalias !119
  %_31.i.i642.sroa.70.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 85
  store i8 0, ptr %_31.i.i642.sroa.70.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !119
  %_31.i.i642.sroa.71.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 86
  store i8 0, ptr %_31.i.i642.sroa.71.0.fresh.i.i644.sroa_idx.i, align 2, !noalias !119
  %_31.i.i642.sroa.72.0.fresh.i.i644.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i644.i, i64 87
  store i8 0, ptr %_31.i.i642.sroa.72.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !119
  %512 = icmp eq i8 %proto1.i.i.i, 6
  %513 = icmp eq i16 %dp.sroa.0.0.i663.i, 443
  %or.cond1.i.i707.i = and i1 %512, %513
  br i1 %or.cond1.i.i707.i, label %bb5.i.i710.i, label %bb7.i.i708.i

bb2.i.i675.i:                                     ; preds = %bb11.i.i670.i
  %_28.i5.i.i677.i = load i32, ptr %ctx, align 4, !noalias !121, !noundef !12
  %_22.i6.i.i678.i = zext i32 %_28.i5.i.i677.i to i64
  %_21.i7.i.i679.i = inttoptr i64 %_22.i6.i.i678.i to ptr
  %_30.i8.i.i680.i = load i32, ptr %0, align 4, !noalias !121, !noundef !12
  %_24.i9.i.i681.i = zext i32 %_30.i8.i.i680.i to i64
  %_23.i10.i.i682.i = inttoptr i64 %_24.i9.i.i681.i to ptr
  %_25.i11.i.i683.i = getelementptr inbounds nuw i8, ptr %_21.i7.i.i679.i, i64 %thlen.pn.i664.i
  %_27.i12.i.i684.i = getelementptr inbounds nuw i8, ptr %_25.i11.i.i683.i, i64 1
  %_26.i13.i.i685.i = icmp samesign ugt ptr %_27.i12.i.i684.i, %_23.i10.i.i682.i
  br i1 %_26.i13.i.i685.i, label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i672.i, label %bb10.i14.i.i686.i

bb10.i14.i.i686.i:                                ; preds = %bb2.i.i675.i
  %_6.i15.i.i687.i = load i8, ptr %_25.i11.i.i683.i, align 1, !noalias !121, !noundef !12
  %514 = icmp ne i8 %_6.i15.i.i687.i, 22
  %_39.i17.i.i690.i = getelementptr i8, ptr %_25.i11.i.i683.i, i64 21
  %_38.i18.i.i691.i = icmp samesign ugt ptr %_39.i17.i.i690.i, %_23.i10.i.i682.i
  %or.cond774.i = or i1 %_38.i18.i.i691.i, %514
  br i1 %or.cond774.i, label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i672.i, label %bb12.i19.i.i692.i

bb12.i19.i.i692.i:                                ; preds = %bb10.i14.i.i686.i
  %_37.i20.i.i693.i = getelementptr i8, ptr %_25.i11.i.i683.i, i64 5
  %_13.i21.i.i694.i = getelementptr inbounds nuw i8, ptr %_0.i18, i64 24
  call void @llvm.memcpy.p0.p0.i64(ptr noundef nonnull align 1 dereferenceable(16) %_13.i21.i.i694.i, ptr noundef nonnull align 1 dereferenceable(16) %_37.i20.i.i693.i, i64 16, i1 false), !noalias !121
  %515 = getelementptr inbounds nuw i8, ptr %_0.i18, i64 25
  %516 = getelementptr inbounds nuw i8, ptr %_0.i18, i64 26
  %517 = getelementptr inbounds nuw i8, ptr %_0.i18, i64 27
  %518 = getelementptr inbounds nuw i8, ptr %_0.i18, i64 28
  %519 = getelementptr inbounds nuw i8, ptr %_0.i18, i64 29
  %520 = getelementptr inbounds nuw i8, ptr %_0.i18, i64 30
  %521 = getelementptr inbounds nuw i8, ptr %_0.i18, i64 31
  %522 = getelementptr inbounds nuw i8, ptr %_0.i18, i64 32
  %523 = getelementptr inbounds nuw i8, ptr %_0.i18, i64 33
  %524 = getelementptr inbounds nuw i8, ptr %_0.i18, i64 34
  %525 = getelementptr inbounds nuw i8, ptr %_0.i18, i64 35
  %526 = getelementptr inbounds nuw i8, ptr %_0.i18, i64 36
  %527 = getelementptr inbounds nuw i8, ptr %_0.i18, i64 37
  %528 = getelementptr inbounds nuw i8, ptr %_0.i18, i64 38
  %529 = getelementptr inbounds nuw i8, ptr %_0.i18, i64 39
  %530 = load <16 x i8>, ptr %_13.i21.i.i694.i, align 8, !noalias !121
  %531 = add <16 x i8> %530, splat (i8 -32)
  %532 = icmp ult <16 x i8> %531, splat (i8 95)
  %533 = select <16 x i1> %532, <16 x i8> %530, <16 x i8> zeroinitializer
  %534 = extractelement <16 x i8> %533, i64 0
  store i8 %534, ptr %_13.i21.i.i694.i, align 8, !noalias !121
  %535 = extractelement <16 x i8> %533, i64 1
  store i8 %535, ptr %515, align 1, !noalias !121
  %536 = extractelement <16 x i8> %533, i64 2
  store i8 %536, ptr %516, align 2, !noalias !121
  %537 = extractelement <16 x i8> %533, i64 3
  store i8 %537, ptr %517, align 1, !noalias !121
  %538 = extractelement <16 x i8> %533, i64 4
  store i8 %538, ptr %518, align 4, !noalias !121
  %539 = extractelement <16 x i8> %533, i64 5
  store i8 %539, ptr %519, align 1, !noalias !121
  %540 = extractelement <16 x i8> %533, i64 6
  store i8 %540, ptr %520, align 2, !noalias !121
  %541 = extractelement <16 x i8> %533, i64 7
  store i8 %541, ptr %521, align 1, !noalias !121
  %542 = extractelement <16 x i8> %533, i64 8
  store i8 %542, ptr %522, align 8, !noalias !121
  %543 = extractelement <16 x i8> %533, i64 9
  store i8 %543, ptr %523, align 1, !noalias !121
  %544 = extractelement <16 x i8> %533, i64 10
  store i8 %544, ptr %524, align 2, !noalias !121
  %545 = extractelement <16 x i8> %533, i64 11
  store i8 %545, ptr %525, align 1, !noalias !121
  %546 = extractelement <16 x i8> %533, i64 12
  store i8 %546, ptr %526, align 4, !noalias !121
  %547 = extractelement <16 x i8> %533, i64 13
  store i8 %547, ptr %527, align 1, !noalias !121
  %548 = extractelement <16 x i8> %533, i64 14
  store i8 %548, ptr %528, align 2, !noalias !121
  %549 = extractelement <16 x i8> %533, i64 15
  store i8 %549, ptr %529, align 1, !noalias !121
  br label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i672.i

bb7.i.i708.i:                                     ; preds = %bb12.i.i.i727.i, %bb10.i.i.i721.i, %bb5.i.i710.i, %bb10.i.i702.i
  %_0.i19 = call noundef i64 inttoptr (i64 2 to ptr)(ptr noundef nonnull @FLOW_METRICS, ptr noundef nonnull readonly align 4 dereferenceable(16) %key.i645.i, ptr noundef nonnull %fresh.i.i644.i, i64 noundef 0) #5
  call void @llvm.lifetime.end.p0(ptr nonnull %fresh.i.i644.i), !noalias !119
  br label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i672.i

bb5.i.i710.i:                                     ; preds = %bb10.i.i702.i
  %_28.i.i.i712.i = load i32, ptr %ctx, align 4, !noalias !124, !noundef !12
  %_22.i.i.i713.i = zext i32 %_28.i.i.i712.i to i64
  %_21.i.i.i714.i = inttoptr i64 %_22.i.i.i713.i to ptr
  %_30.i.i.i715.i = load i32, ptr %0, align 4, !noalias !124, !noundef !12
  %_24.i.i.i716.i = zext i32 %_30.i.i.i715.i to i64
  %_23.i.i.i717.i = inttoptr i64 %_24.i.i.i716.i to ptr
  %_25.i.i.i718.i = getelementptr inbounds nuw i8, ptr %_21.i.i.i714.i, i64 %thlen.pn.i664.i
  %_27.i.i.i719.i = getelementptr inbounds nuw i8, ptr %_25.i.i.i718.i, i64 1
  %_26.i.i.i720.i = icmp samesign ugt ptr %_27.i.i.i719.i, %_23.i.i.i717.i
  br i1 %_26.i.i.i720.i, label %bb7.i.i708.i, label %bb10.i.i.i721.i

bb10.i.i.i721.i:                                  ; preds = %bb5.i.i710.i
  %_6.i.i.i722.i = load i8, ptr %_25.i.i.i718.i, align 1, !noalias !124, !noundef !12
  %550 = icmp ne i8 %_6.i.i.i722.i, 22
  %_39.i.i.i725.i = getelementptr i8, ptr %_25.i.i.i718.i, i64 21
  %_38.i.i.i726.i = icmp samesign ugt ptr %_39.i.i.i725.i, %_23.i.i.i717.i
  %or.cond775.i = or i1 %_38.i.i.i726.i, %550
  br i1 %or.cond775.i, label %bb7.i.i708.i, label %bb12.i.i.i727.i

bb12.i.i.i727.i:                                  ; preds = %bb10.i.i.i721.i
  %_37.i.i.i728.i = getelementptr i8, ptr %_25.i.i.i718.i, i64 5
  call void @llvm.memcpy.p0.p0.i64(ptr noundef nonnull align 8 dereferenceable(16) %_31.i.i642.sroa.9.0.fresh.i.i644.sroa_idx.i, ptr noundef nonnull align 1 dereferenceable(16) %_37.i.i.i728.i, i64 16, i1 false), !noalias !124
  %551 = load <16 x i8>, ptr %_31.i.i642.sroa.9.0.fresh.i.i644.sroa_idx.i, align 8, !noalias !127
  %552 = add <16 x i8> %551, splat (i8 -32)
  %553 = icmp ult <16 x i8> %552, splat (i8 95)
  %554 = select <16 x i1> %553, <16 x i8> %551, <16 x i8> zeroinitializer
  %555 = extractelement <16 x i8> %554, i64 0
  store i8 %555, ptr %_31.i.i642.sroa.9.0.fresh.i.i644.sroa_idx.i, align 8, !noalias !127
  %556 = extractelement <16 x i8> %554, i64 1
  store i8 %556, ptr %_31.i.i642.sroa.10.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !127
  %557 = extractelement <16 x i8> %554, i64 2
  store i8 %557, ptr %_31.i.i642.sroa.11.0.fresh.i.i644.sroa_idx.i, align 2, !noalias !127
  %558 = extractelement <16 x i8> %554, i64 3
  store i8 %558, ptr %_31.i.i642.sroa.12.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !127
  %559 = extractelement <16 x i8> %554, i64 4
  store i8 %559, ptr %_31.i.i642.sroa.13.0.fresh.i.i644.sroa_idx.i, align 4, !noalias !127
  %560 = extractelement <16 x i8> %554, i64 5
  store i8 %560, ptr %_31.i.i642.sroa.14.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !127
  %561 = extractelement <16 x i8> %554, i64 6
  store i8 %561, ptr %_31.i.i642.sroa.15.0.fresh.i.i644.sroa_idx.i, align 2, !noalias !127
  %562 = extractelement <16 x i8> %554, i64 7
  store i8 %562, ptr %_31.i.i642.sroa.16.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !127
  %563 = extractelement <16 x i8> %554, i64 8
  store i8 %563, ptr %_31.i.i642.sroa.17.0.fresh.i.i644.sroa_idx.i, align 8, !noalias !127
  %564 = extractelement <16 x i8> %554, i64 9
  store i8 %564, ptr %_31.i.i642.sroa.18.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !127
  %565 = extractelement <16 x i8> %554, i64 10
  store i8 %565, ptr %_31.i.i642.sroa.19.0.fresh.i.i644.sroa_idx.i, align 2, !noalias !127
  %566 = extractelement <16 x i8> %554, i64 11
  store i8 %566, ptr %_31.i.i642.sroa.20.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !127
  %567 = extractelement <16 x i8> %554, i64 12
  store i8 %567, ptr %_31.i.i642.sroa.21.0.fresh.i.i644.sroa_idx.i, align 4, !noalias !127
  %568 = extractelement <16 x i8> %554, i64 13
  store i8 %568, ptr %_31.i.i642.sroa.22.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !127
  %569 = extractelement <16 x i8> %554, i64 14
  store i8 %569, ptr %_31.i.i642.sroa.23.0.fresh.i.i644.sroa_idx.i, align 2, !noalias !127
  %570 = extractelement <16 x i8> %554, i64 15
  store i8 %570, ptr %_31.i.i642.sroa.24.0.fresh.i.i644.sroa_idx.i, align 1, !noalias !127
  br label %bb7.i.i708.i

_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i672.i: ; preds = %bb7.i.i708.i, %bb12.i19.i.i692.i, %bb10.i14.i.i686.i, %bb2.i.i675.i, %bb11.i.i670.i
  call void @llvm.lifetime.end.p0(ptr nonnull %key.i645.i), !noalias !113
  br label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv610parse_ipv6.exit.i

bb13.i657.i:                                      ; preds = %bb5.i646.i
  %_48.i654.i = getelementptr inbounds nuw i8, ptr %_43.i650.i, i64 124
  %_23.i658.i = load i16, ptr %_48.i654.i, align 2, !noalias !113, !noundef !12
  %571 = tail call i16 @llvm.bswap.i16(i16 %_23.i658.i)
  %572 = getelementptr inbounds nuw i8, ptr %_43.i650.i, i64 126
  %_25.i659.i = load i16, ptr %572, align 2, !noalias !113, !noundef !12
  %573 = tail call i16 @llvm.bswap.i16(i16 %_25.i659.i)
  br label %bb6.i660.i

bb4.i26.i:                                        ; preds = %bb13.i18.i
  %_70.i.i = inttoptr i64 %_15.i21.i to ptr
  %_72.i.i = inttoptr i64 %_14.i20.i to ptr
  %_77.i.i = getelementptr inbounds nuw i8, ptr %_70.i.i, i64 62
  %_76.i.i = icmp samesign ugt ptr %_77.i.i, %_72.i.i
  br i1 %_76.i.i, label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv610parse_ipv6.exit.i, label %bb18.i.i

bb18.i.i:                                         ; preds = %bb4.i26.i
  %_75.i.i = getelementptr inbounds nuw i8, ptr %_70.i.i, i64 54
  call void @llvm.lifetime.start.p0(ptr nonnull %key.i7.i), !noalias !72
  %_36.i27.i = load i8, ptr %_75.i.i, align 2, !noalias !72, !noundef !12
  %_35.i.i = zext i8 %_36.i27.i to i16
  %574 = getelementptr inbounds nuw i8, ptr %_70.i.i, i64 55
  %_38.i28.i = load i8, ptr %574, align 1, !noalias !72, !noundef !12
  %_37.i29.i = zext i8 %_38.i28.i to i16
  store i32 %src_lo.i.i, ptr %key.i7.i, align 4, !noalias !72
  %575 = getelementptr inbounds nuw i8, ptr %key.i7.i, i64 4
  store i32 %dst_lo.i.i, ptr %575, align 4, !noalias !72
  %576 = getelementptr inbounds nuw i8, ptr %key.i7.i, i64 8
  store i16 %_35.i.i, ptr %576, align 4, !noalias !72
  %577 = getelementptr inbounds nuw i8, ptr %key.i7.i, i64 10
  store i16 %_37.i29.i, ptr %577, align 2, !noalias !72
  %578 = getelementptr inbounds nuw i8, ptr %key.i7.i, i64 12
  store i8 58, ptr %578, align 4, !noalias !72
  %579 = getelementptr inbounds nuw i8, ptr %key.i7.i, i64 13
  store i8 0, ptr %579, align 1, !noalias !72
  %_39.sroa.4.0..sroa_idx.i.i = getelementptr inbounds nuw i8, ptr %key.i7.i, i64 14
  store i8 0, ptr %_39.sroa.4.0..sroa_idx.i.i, align 2, !noalias !72
  %_39.sroa.5.0..sroa_idx.i.i = getelementptr inbounds nuw i8, ptr %key.i7.i, i64 15
  store i8 0, ptr %_39.sroa.5.0..sroa_idx.i.i, align 1, !noalias !72
  %_0.i20 = call noundef ptr inttoptr (i64 1 to ptr)(ptr noundef nonnull @FLOW_METRICS, ptr noundef nonnull readonly align 4 dereferenceable(16) %key.i7.i) #5, !noalias !72
  %_13.i.i31.i = icmp eq ptr %_0.i20, null
  br i1 %_13.i.i31.i, label %bb3.i.i34.i, label %bb4.i.i32.i

bb4.i.i32.i:                                      ; preds = %bb18.i.i
  %580 = getelementptr inbounds nuw i8, ptr %_0.i20, i64 8
  %581 = load <2 x i64>, ptr %_0.i20, align 8, !noalias !72
  %582 = insertelement <2 x i64> <i64 poison, i64 1>, i64 %_13.i22.i, i64 0
  %583 = add <2 x i64> %581, %582
  %584 = extractelement <2 x i64> %583, i64 0
  store i64 %584, ptr %_0.i20, align 8, !noalias !72
  %585 = extractelement <2 x i64> %583, i64 1
  store i64 %585, ptr %580, align 8, !noalias !72
  br label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics14update_metrics.exit.i33.i

bb3.i.i34.i:                                      ; preds = %bb18.i.i
  call void @llvm.lifetime.start.p0(ptr nonnull %fresh.i.i6.i), !noalias !128
  store i64 %_13.i22.i, ptr %fresh.i.i6.i, align 8, !noalias !128
  %_24.i.i4.sroa.4.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 8
  store i64 1, ptr %_24.i.i4.sroa.4.0.fresh.i.i6.sroa_idx.i, align 8, !noalias !128
  %_24.i.i4.sroa.5.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 16
  store i8 0, ptr %_24.i.i4.sroa.5.0.fresh.i.i6.sroa_idx.i, align 8, !noalias !128
  %_24.i.i4.sroa.6.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 17
  store i8 0, ptr %_24.i.i4.sroa.6.0.fresh.i.i6.sroa_idx.i, align 1, !noalias !128
  %_24.i.i4.sroa.7.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 18
  store i16 0, ptr %_24.i.i4.sroa.7.0.fresh.i.i6.sroa_idx.i, align 2, !noalias !128
  %_24.i.i4.sroa.8.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 20
  store i32 0, ptr %_24.i.i4.sroa.8.0.fresh.i.i6.sroa_idx.i, align 4, !noalias !128
  %_24.i.i4.sroa.9.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 24
  store i8 0, ptr %_24.i.i4.sroa.9.0.fresh.i.i6.sroa_idx.i, align 8, !noalias !128
  %_24.i.i4.sroa.10.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 25
  store i8 0, ptr %_24.i.i4.sroa.10.0.fresh.i.i6.sroa_idx.i, align 1, !noalias !128
  %_24.i.i4.sroa.11.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 26
  store i8 0, ptr %_24.i.i4.sroa.11.0.fresh.i.i6.sroa_idx.i, align 2, !noalias !128
  %_24.i.i4.sroa.12.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 27
  store i8 0, ptr %_24.i.i4.sroa.12.0.fresh.i.i6.sroa_idx.i, align 1, !noalias !128
  %_24.i.i4.sroa.13.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 28
  store i8 0, ptr %_24.i.i4.sroa.13.0.fresh.i.i6.sroa_idx.i, align 4, !noalias !128
  %_24.i.i4.sroa.14.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 29
  store i8 0, ptr %_24.i.i4.sroa.14.0.fresh.i.i6.sroa_idx.i, align 1, !noalias !128
  %_24.i.i4.sroa.15.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 30
  store i8 0, ptr %_24.i.i4.sroa.15.0.fresh.i.i6.sroa_idx.i, align 2, !noalias !128
  %_24.i.i4.sroa.16.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 31
  store i8 0, ptr %_24.i.i4.sroa.16.0.fresh.i.i6.sroa_idx.i, align 1, !noalias !128
  %_24.i.i4.sroa.17.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 32
  store i8 0, ptr %_24.i.i4.sroa.17.0.fresh.i.i6.sroa_idx.i, align 8, !noalias !128
  %_24.i.i4.sroa.18.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 33
  store i8 0, ptr %_24.i.i4.sroa.18.0.fresh.i.i6.sroa_idx.i, align 1, !noalias !128
  %_24.i.i4.sroa.19.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 34
  store i8 0, ptr %_24.i.i4.sroa.19.0.fresh.i.i6.sroa_idx.i, align 2, !noalias !128
  %_24.i.i4.sroa.20.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 35
  store i8 0, ptr %_24.i.i4.sroa.20.0.fresh.i.i6.sroa_idx.i, align 1, !noalias !128
  %_24.i.i4.sroa.21.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 36
  store i8 0, ptr %_24.i.i4.sroa.21.0.fresh.i.i6.sroa_idx.i, align 4, !noalias !128
  %_24.i.i4.sroa.22.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 37
  store i8 0, ptr %_24.i.i4.sroa.22.0.fresh.i.i6.sroa_idx.i, align 1, !noalias !128
  %_24.i.i4.sroa.23.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 38
  store i8 0, ptr %_24.i.i4.sroa.23.0.fresh.i.i6.sroa_idx.i, align 2, !noalias !128
  %_24.i.i4.sroa.24.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 39
  store i8 0, ptr %_24.i.i4.sroa.24.0.fresh.i.i6.sroa_idx.i, align 1, !noalias !128
  %_24.i.i4.sroa.25.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 40
  store i8 0, ptr %_24.i.i4.sroa.25.0.fresh.i.i6.sroa_idx.i, align 8, !noalias !128
  %_24.i.i4.sroa.26.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 41
  store i8 0, ptr %_24.i.i4.sroa.26.0.fresh.i.i6.sroa_idx.i, align 1, !noalias !128
  %_24.i.i4.sroa.27.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 42
  store i8 0, ptr %_24.i.i4.sroa.27.0.fresh.i.i6.sroa_idx.i, align 2, !noalias !128
  %_24.i.i4.sroa.28.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 43
  store i8 0, ptr %_24.i.i4.sroa.28.0.fresh.i.i6.sroa_idx.i, align 1, !noalias !128
  %_24.i.i4.sroa.29.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 44
  store i8 0, ptr %_24.i.i4.sroa.29.0.fresh.i.i6.sroa_idx.i, align 4, !noalias !128
  %_24.i.i4.sroa.30.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 45
  store i8 0, ptr %_24.i.i4.sroa.30.0.fresh.i.i6.sroa_idx.i, align 1, !noalias !128
  %_24.i.i4.sroa.31.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 46
  store i8 0, ptr %_24.i.i4.sroa.31.0.fresh.i.i6.sroa_idx.i, align 2, !noalias !128
  %_24.i.i4.sroa.32.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 47
  store i8 0, ptr %_24.i.i4.sroa.32.0.fresh.i.i6.sroa_idx.i, align 1, !noalias !128
  %_24.i.i4.sroa.33.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 48
  store i8 0, ptr %_24.i.i4.sroa.33.0.fresh.i.i6.sroa_idx.i, align 8, !noalias !128
  %_24.i.i4.sroa.34.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 49
  store i8 0, ptr %_24.i.i4.sroa.34.0.fresh.i.i6.sroa_idx.i, align 1, !noalias !128
  %_24.i.i4.sroa.35.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 50
  store i8 0, ptr %_24.i.i4.sroa.35.0.fresh.i.i6.sroa_idx.i, align 2, !noalias !128
  %_24.i.i4.sroa.36.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 51
  store i8 0, ptr %_24.i.i4.sroa.36.0.fresh.i.i6.sroa_idx.i, align 1, !noalias !128
  %_24.i.i4.sroa.37.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 52
  store i8 0, ptr %_24.i.i4.sroa.37.0.fresh.i.i6.sroa_idx.i, align 4, !noalias !128
  %_24.i.i4.sroa.38.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 53
  store i8 0, ptr %_24.i.i4.sroa.38.0.fresh.i.i6.sroa_idx.i, align 1, !noalias !128
  %_24.i.i4.sroa.39.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 54
  store i8 0, ptr %_24.i.i4.sroa.39.0.fresh.i.i6.sroa_idx.i, align 2, !noalias !128
  %_24.i.i4.sroa.40.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 55
  store i8 0, ptr %_24.i.i4.sroa.40.0.fresh.i.i6.sroa_idx.i, align 1, !noalias !128
  %_24.i.i4.sroa.41.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 56
  store i8 0, ptr %_24.i.i4.sroa.41.0.fresh.i.i6.sroa_idx.i, align 8, !noalias !128
  %_24.i.i4.sroa.42.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 57
  store i8 0, ptr %_24.i.i4.sroa.42.0.fresh.i.i6.sroa_idx.i, align 1, !noalias !128
  %_24.i.i4.sroa.43.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 58
  store i8 0, ptr %_24.i.i4.sroa.43.0.fresh.i.i6.sroa_idx.i, align 2, !noalias !128
  %_24.i.i4.sroa.44.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 59
  store i8 0, ptr %_24.i.i4.sroa.44.0.fresh.i.i6.sroa_idx.i, align 1, !noalias !128
  %_24.i.i4.sroa.45.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 60
  store i8 0, ptr %_24.i.i4.sroa.45.0.fresh.i.i6.sroa_idx.i, align 4, !noalias !128
  %_24.i.i4.sroa.46.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 61
  store i8 0, ptr %_24.i.i4.sroa.46.0.fresh.i.i6.sroa_idx.i, align 1, !noalias !128
  %_24.i.i4.sroa.47.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 62
  store i8 0, ptr %_24.i.i4.sroa.47.0.fresh.i.i6.sroa_idx.i, align 2, !noalias !128
  %_24.i.i4.sroa.48.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 63
  store i8 0, ptr %_24.i.i4.sroa.48.0.fresh.i.i6.sroa_idx.i, align 1, !noalias !128
  %_24.i.i4.sroa.49.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 64
  store i8 0, ptr %_24.i.i4.sroa.49.0.fresh.i.i6.sroa_idx.i, align 8, !noalias !128
  %_24.i.i4.sroa.50.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 65
  store i8 0, ptr %_24.i.i4.sroa.50.0.fresh.i.i6.sroa_idx.i, align 1, !noalias !128
  %_24.i.i4.sroa.51.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 66
  store i8 0, ptr %_24.i.i4.sroa.51.0.fresh.i.i6.sroa_idx.i, align 2, !noalias !128
  %_24.i.i4.sroa.52.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 67
  store i8 0, ptr %_24.i.i4.sroa.52.0.fresh.i.i6.sroa_idx.i, align 1, !noalias !128
  %_24.i.i4.sroa.53.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 68
  store i8 0, ptr %_24.i.i4.sroa.53.0.fresh.i.i6.sroa_idx.i, align 4, !noalias !128
  %_24.i.i4.sroa.54.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 69
  store i8 0, ptr %_24.i.i4.sroa.54.0.fresh.i.i6.sroa_idx.i, align 1, !noalias !128
  %_24.i.i4.sroa.55.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 70
  store i8 0, ptr %_24.i.i4.sroa.55.0.fresh.i.i6.sroa_idx.i, align 2, !noalias !128
  %_24.i.i4.sroa.56.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 71
  store i8 0, ptr %_24.i.i4.sroa.56.0.fresh.i.i6.sroa_idx.i, align 1, !noalias !128
  %_24.i.i4.sroa.57.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 72
  store i8 0, ptr %_24.i.i4.sroa.57.0.fresh.i.i6.sroa_idx.i, align 8, !noalias !128
  %_24.i.i4.sroa.58.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 73
  store i8 0, ptr %_24.i.i4.sroa.58.0.fresh.i.i6.sroa_idx.i, align 1, !noalias !128
  %_24.i.i4.sroa.59.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 74
  store i8 0, ptr %_24.i.i4.sroa.59.0.fresh.i.i6.sroa_idx.i, align 2, !noalias !128
  %_24.i.i4.sroa.60.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 75
  store i8 0, ptr %_24.i.i4.sroa.60.0.fresh.i.i6.sroa_idx.i, align 1, !noalias !128
  %_24.i.i4.sroa.61.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 76
  store i8 0, ptr %_24.i.i4.sroa.61.0.fresh.i.i6.sroa_idx.i, align 4, !noalias !128
  %_24.i.i4.sroa.62.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 77
  store i8 0, ptr %_24.i.i4.sroa.62.0.fresh.i.i6.sroa_idx.i, align 1, !noalias !128
  %_24.i.i4.sroa.63.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 78
  store i8 0, ptr %_24.i.i4.sroa.63.0.fresh.i.i6.sroa_idx.i, align 2, !noalias !128
  %_24.i.i4.sroa.64.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 79
  store i8 0, ptr %_24.i.i4.sroa.64.0.fresh.i.i6.sroa_idx.i, align 1, !noalias !128
  %_24.i.i4.sroa.65.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 80
  store i8 0, ptr %_24.i.i4.sroa.65.0.fresh.i.i6.sroa_idx.i, align 8, !noalias !128
  %_24.i.i4.sroa.66.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 81
  store i8 0, ptr %_24.i.i4.sroa.66.0.fresh.i.i6.sroa_idx.i, align 1, !noalias !128
  %_24.i.i4.sroa.67.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 82
  store i8 0, ptr %_24.i.i4.sroa.67.0.fresh.i.i6.sroa_idx.i, align 2, !noalias !128
  %_24.i.i4.sroa.68.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 83
  store i8 0, ptr %_24.i.i4.sroa.68.0.fresh.i.i6.sroa_idx.i, align 1, !noalias !128
  %_24.i.i4.sroa.69.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 84
  store i8 0, ptr %_24.i.i4.sroa.69.0.fresh.i.i6.sroa_idx.i, align 4, !noalias !128
  %_24.i.i4.sroa.70.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 85
  store i8 0, ptr %_24.i.i4.sroa.70.0.fresh.i.i6.sroa_idx.i, align 1, !noalias !128
  %_24.i.i4.sroa.71.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 86
  store i8 0, ptr %_24.i.i4.sroa.71.0.fresh.i.i6.sroa_idx.i, align 2, !noalias !128
  %_24.i.i4.sroa.72.0.fresh.i.i6.sroa_idx.i = getelementptr inbounds nuw i8, ptr %fresh.i.i6.i, i64 87
  store i8 0, ptr %_24.i.i4.sroa.72.0.fresh.i.i6.sroa_idx.i, align 1, !noalias !128
  %_0.i21 = call noundef i64 inttoptr (i64 2 to ptr)(ptr noundef nonnull @FLOW_METRICS, ptr noundef nonnull readonly align 4 dereferenceable(16) %key.i7.i, ptr noundef nonnull %fresh.i.i6.i, i64 noundef 0) #5
  call void @llvm.lifetime.end.p0(ptr nonnull %fresh.i.i6.i), !noalias !128
  br label %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics14update_metrics.exit.i33.i

_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics14update_metrics.exit.i33.i: ; preds = %bb3.i.i34.i, %bb4.i.i32.i
  call void @llvm.lifetime.end.p0(ptr nonnull %key.i7.i), !noalias !72
  br label %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv610parse_ipv6.exit.i

_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv610parse_ipv6.exit.i: ; preds = %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics14update_metrics.exit.i33.i, %bb4.i26.i, %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i672.i, %bb5.i646.i, %bb4.i738.i, %bb15.i7.i.i, %bb8.i.i70.i, %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i559.i, %bb5.i533.i, %bb4.i625.i, %bb12.i11.i.i, %bb10.i10.i.i, %bb2.i6.i.i, %bb3.i.i71.i, %bb7.i69.i, %bb5.i67.i, %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i.i, %bb3.i52.i, %bb1.i.i, %bb13.i18.i, %bb11.i14.i, %bb2.i.i
  %_0.sroa.8.0.i17.i = phi i64 [ 1, %bb2.i.i ], [ 8589934592, %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics14update_metrics.exit.i33.i ], [ 4294967296, %bb11.i14.i ], [ 1, %bb4.i26.i ], [ 8589934592, %bb13.i18.i ], [ 1, %bb3.i52.i ], [ 8589934592, %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i.i ], [ 1, %bb1.i.i ], [ 8589934592, %bb5.i67.i ], [ 1, %bb2.i6.i.i ], [ 8589934592, %bb7.i69.i ], [ 4294967296, %bb8.i.i70.i ], [ 1, %bb3.i.i71.i ], [ 4294967296, %bb10.i10.i.i ], [ 8589934592, %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i559.i ], [ 8589934592, %bb12.i11.i.i ], [ 8589934593, %bb4.i625.i ], [ 8589934593, %bb5.i533.i ], [ 8589934592, %bb15.i7.i.i ], [ 8589934593, %bb4.i738.i ], [ 8589934593, %bb5.i646.i ], [ 8589934592, %_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni.exit.i672.i ]
  %.sroa.45.0.extract.shift.i.i = and i64 %_0.sroa.8.0.i17.i, 12884901888
  br label %_RNvNvCsiBg6FOfWNuR_9mizn_ebpf9mizn_ebpf9mizn_ebpf.exit

_RNvNvCsiBg6FOfWNuR_9mizn_ebpf9mizn_ebpf9mizn_ebpf.exit: ; preds = %start, %bb7.i.i, %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv410parse_ipv4.exit.i, %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv610parse_ipv6.exit.i
  %_0.sroa.5.0.i.i = phi i64 [ %.sroa.45.0.extract.shift.i.i, %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv610parse_ipv6.exit.i ], [ 0, %start ], [ %.sroa.4.0.extract.shift.i.i, %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv410parse_ipv4.exit.i ], [ 8589934592, %bb7.i.i ]
  %_0.sroa.0.0.i.i = phi i64 [ %_0.sroa.8.0.i17.i, %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv610parse_ipv6.exit.i ], [ 1, %start ], [ %_0.sroa.8.0.i.i, %_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv410parse_ipv4.exit.i ], [ 0, %bb7.i.i ]
  %586 = trunc i64 %_0.sroa.0.0.i.i to i1
  %.sroa.4.0.extract.shift.i = lshr exact i64 %_0.sroa.5.0.i.i, 32
  %.sroa.4.0.extract.trunc.i = trunc nuw nsw i64 %.sroa.4.0.extract.shift.i to i32
  %action.sroa.0.0.i = select i1 %586, i32 2, i32 %.sroa.4.0.extract.trunc.i
  ret i32 %action.sroa.0.0.i
}

; Function Attrs: mustprogress nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(ptr captures(none)) #1

; Function Attrs: mustprogress nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias writeonly captures(none), ptr noalias readonly captures(none), i64, i1 immarg) #1

; Function Attrs: mustprogress nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(ptr captures(none)) #1

; Function Attrs: mustprogress nocallback nocreateundeforpoison nofree nosync nounwind speculatable willreturn memory(none)
declare i16 @llvm.bswap.i16(i16) #2

; Function Attrs: mustprogress nocallback nocreateundeforpoison nofree nosync nounwind speculatable willreturn memory(none)
declare i32 @llvm.bswap.i32(i32) #2

; Function Attrs: nofree norecurse nosync nounwind memory(argmem: readwrite)
define hidden void @memcpy(ptr nofree noundef writeonly captures(none) %dest, ptr nofree noundef readonly captures(none) %src, i64 noundef %n) unnamed_addr #3 !guid !131 {
start:
  %_72.not = icmp eq i64 %n, 0
  br i1 %_72.not, label %bb3, label %bb2

bb3:                                              ; preds = %bb2, %start
  ret void

bb2:                                              ; preds = %start, %bb2
  %_9.sroa.0.03 = phi i64 [ %0, %bb2 ], [ 0, %start ]
  %0 = add nuw i64 %_9.sroa.0.03, 1
  %_5 = getelementptr inbounds nuw i8, ptr %src, i64 %_9.sroa.0.03
  %_4 = load i8, ptr %_5, align 1, !noundef !12
  %_6 = getelementptr inbounds nuw i8, ptr %dest, i64 %_9.sroa.0.03
  store i8 %_4, ptr %_6, align 1
  %_7 = icmp ult i64 %0, %n
  br i1 %_7, label %bb2, label %bb3
}

; Function Attrs: nofree norecurse nosync nounwind memory(argmem: readwrite)
define hidden void @memmove(ptr noundef %dest, ptr noundef %src, i64 noundef %0) unnamed_addr #3 !guid !132 {
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
  %_15 = load i8, ptr %_16, align 1, !noundef !12
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
  %_8 = load i8, ptr %_9, align 1, !noundef !12
  %_10 = getelementptr inbounds nuw i8, ptr %dest, i64 %_13.sroa.0.08
  store i8 %_8, ptr %_10, align 1
  %_11 = icmp ult i64 %1, %0
  br i1 %_11, label %bb5, label %bb3
}

; Function Attrs: nofree norecurse nosync nounwind memory(argmem: write)
define hidden void @memset(ptr nofree noundef writeonly captures(none) %s, i32 noundef %c, i64 noundef %n) unnamed_addr #4 !guid !133 {
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

attributes #0 = { nounwind "target-cpu"="generic" }
attributes #1 = { mustprogress nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { mustprogress nocallback nocreateundeforpoison nofree nosync nounwind speculatable willreturn memory(none) }
attributes #3 = { nofree norecurse nosync nounwind memory(argmem: readwrite) "target-cpu"="generic" }
attributes #4 = { nofree norecurse nosync nounwind memory(argmem: write) "target-cpu"="generic" }
attributes #5 = { nounwind }

!llvm.module.flags = !{!4, !5, !6}
!llvm.ident = !{!7}

!0 = !{i64 -1777206517905316127}
!1 = !{i64 3337506620901943582}
!2 = !{i64 -2826757848730482758}
!3 = !{i64 -3547617569760469716}
!4 = !{i32 8, !"PIC Level", i32 2}
!5 = !{i32 7, !"PIE Level", i32 2}
!6 = !{i32 1, !"ThinLTO", i32 0}
!7 = !{!"rustc version 1.100.0-nightly (a69a63265 2026-09-03)"}
!8 = !{i64 5475823469477187496}
!9 = !{!10}
!10 = distinct !{!10, !11, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7parsing14process_packet: %ctx"}
!11 = distinct !{!11, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7parsing14process_packet"}
!12 = !{}
!13 = !{!14}
!14 = distinct !{!14, !15, !"_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv410parse_ipv4: %ctx"}
!15 = distinct !{!15, !"_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv410parse_ipv4"}
!16 = !{!17, !19}
!17 = distinct !{!17, !18, !"_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing9transport19handle_transport_v4: %ctx"}
!18 = distinct !{!18, !"_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing9transport19handle_transport_v4"}
!19 = distinct !{!19, !18, !"_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing9transport19handle_transport_v4: %args"}
!20 = !{!21, !17, !19}
!21 = distinct !{!21, !22, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni: %ctx"}
!22 = distinct !{!22, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni"}
!23 = !{!21, !24, !17, !19}
!24 = distinct !{!24, !22, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni: %key"}
!25 = !{!26, !21, !17, !19}
!26 = distinct !{!26, !27, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics13parse_tls_sni: %ctx"}
!27 = distinct !{!27, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics13parse_tls_sni"}
!28 = !{!29, !21, !17, !19}
!29 = distinct !{!29, !30, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics13parse_tls_sni: %ctx"}
!30 = distinct !{!30, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics13parse_tls_sni"}
!31 = !{!29, !21, !24, !17, !19}
!32 = !{!33, !35, !19}
!33 = distinct !{!33, !34, !"_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing9transport22inner_ip_off_for_vxlan: %_0"}
!34 = distinct !{!34, !"_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing9transport22inner_ip_off_for_vxlan"}
!35 = distinct !{!35, !34, !"_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing9transport22inner_ip_off_for_vxlan: %ctx"}
!36 = !{!37, !19}
!37 = distinct !{!37, !38, !"_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing9transport13dispatch_flat: %ctx"}
!38 = distinct !{!38, !"_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing9transport13dispatch_flat"}
!39 = !{!40, !19}
!40 = distinct !{!40, !41, !"_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing9transport22process_transport_flat: %ctx"}
!41 = distinct !{!41, !"_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing9transport22process_transport_flat"}
!42 = !{!43, !40, !19}
!43 = distinct !{!43, !44, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni: %ctx"}
!44 = distinct !{!44, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni"}
!45 = !{!43, !46, !40, !19}
!46 = distinct !{!46, !44, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni: %key"}
!47 = !{!48, !43, !40, !19}
!48 = distinct !{!48, !49, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics13parse_tls_sni: %ctx"}
!49 = distinct !{!49, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics13parse_tls_sni"}
!50 = !{!51, !43, !40, !19}
!51 = distinct !{!51, !52, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics13parse_tls_sni: %ctx"}
!52 = distinct !{!52, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics13parse_tls_sni"}
!53 = !{!51, !43, !46, !40, !19}
!54 = !{!55, !19}
!55 = distinct !{!55, !56, !"_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing9transport22process_transport_flat: %ctx"}
!56 = distinct !{!56, !"_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing9transport22process_transport_flat"}
!57 = !{!58, !55, !19}
!58 = distinct !{!58, !59, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni: %ctx"}
!59 = distinct !{!59, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni"}
!60 = !{!58, !61, !55, !19}
!61 = distinct !{!61, !59, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni: %key"}
!62 = !{!63, !58, !55, !19}
!63 = distinct !{!63, !64, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics13parse_tls_sni: %ctx"}
!64 = distinct !{!64, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics13parse_tls_sni"}
!65 = !{!66, !58, !55, !19}
!66 = distinct !{!66, !67, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics13parse_tls_sni: %ctx"}
!67 = distinct !{!67, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics13parse_tls_sni"}
!68 = !{!66, !58, !61, !55, !19}
!69 = !{!70, !14}
!70 = distinct !{!70, !71, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics14update_metrics: %key"}
!71 = distinct !{!71, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics14update_metrics"}
!72 = !{!73}
!73 = distinct !{!73, !74, !"_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv610parse_ipv6: %ctx"}
!74 = distinct !{!74, !"_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing4ipv610parse_ipv6"}
!75 = !{!76, !78}
!76 = distinct !{!76, !77, !"_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing9transport19handle_transport_v4: %ctx"}
!77 = distinct !{!77, !"_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing9transport19handle_transport_v4"}
!78 = distinct !{!78, !77, !"_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing9transport19handle_transport_v4: %args"}
!79 = !{!80, !76, !78}
!80 = distinct !{!80, !81, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni: %ctx"}
!81 = distinct !{!81, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni"}
!82 = !{!80, !83, !76, !78}
!83 = distinct !{!83, !81, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni: %key"}
!84 = !{!85, !80, !76, !78}
!85 = distinct !{!85, !86, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics13parse_tls_sni: %ctx"}
!86 = distinct !{!86, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics13parse_tls_sni"}
!87 = !{!88, !80, !76, !78}
!88 = distinct !{!88, !89, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics13parse_tls_sni: %ctx"}
!89 = distinct !{!89, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics13parse_tls_sni"}
!90 = !{!88, !80, !83, !76, !78}
!91 = !{!92, !94, !78}
!92 = distinct !{!92, !93, !"_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing9transport22inner_ip_off_for_vxlan: %_0"}
!93 = distinct !{!93, !"_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing9transport22inner_ip_off_for_vxlan"}
!94 = distinct !{!94, !93, !"_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing9transport22inner_ip_off_for_vxlan: %ctx"}
!95 = !{!96, !78}
!96 = distinct !{!96, !97, !"_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing9transport13dispatch_flat: %ctx"}
!97 = distinct !{!97, !"_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing9transport13dispatch_flat"}
!98 = !{!99, !78}
!99 = distinct !{!99, !100, !"_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing9transport22process_transport_flat: %ctx"}
!100 = distinct !{!100, !"_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing9transport22process_transport_flat"}
!101 = !{!102, !99, !78}
!102 = distinct !{!102, !103, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni: %ctx"}
!103 = distinct !{!103, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni"}
!104 = !{!102, !105, !99, !78}
!105 = distinct !{!105, !103, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni: %key"}
!106 = !{!107, !102, !99, !78}
!107 = distinct !{!107, !108, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics13parse_tls_sni: %ctx"}
!108 = distinct !{!108, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics13parse_tls_sni"}
!109 = !{!110, !102, !99, !78}
!110 = distinct !{!110, !111, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics13parse_tls_sni: %ctx"}
!111 = distinct !{!111, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics13parse_tls_sni"}
!112 = !{!110, !102, !105, !99, !78}
!113 = !{!114, !78}
!114 = distinct !{!114, !115, !"_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing9transport22process_transport_flat: %ctx"}
!115 = distinct !{!115, !"_RNvNtNtCsiBg6FOfWNuR_9mizn_ebpf7parsing9transport22process_transport_flat"}
!116 = !{!117, !114, !78}
!117 = distinct !{!117, !118, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni: %ctx"}
!118 = distinct !{!118, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni"}
!119 = !{!117, !120, !114, !78}
!120 = distinct !{!120, !118, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics23update_metrics_with_sni: %key"}
!121 = !{!122, !117, !114, !78}
!122 = distinct !{!122, !123, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics13parse_tls_sni: %ctx"}
!123 = distinct !{!123, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics13parse_tls_sni"}
!124 = !{!125, !117, !114, !78}
!125 = distinct !{!125, !126, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics13parse_tls_sni: %ctx"}
!126 = distinct !{!126, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics13parse_tls_sni"}
!127 = !{!125, !117, !120, !114, !78}
!128 = !{!129, !73}
!129 = distinct !{!129, !130, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics14update_metrics: %key"}
!130 = distinct !{!130, !"_RNvNtCsiBg6FOfWNuR_9mizn_ebpf7metrics14update_metrics"}
!131 = !{i64 3893303423671325810}
!132 = !{i64 -306081897096246147}
!133 = !{i64 -2741574704065975695}
