<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ include file="../template/head.jsp" %>
<%@ include file="../template/left.jsp" %>


<script>
	$(document).ready(function () {


		$("#btnSave").click(fnSaveDeviceMange);
		$("#btnManage").click(fnManage);



		// 디바이스 등록 버튼
		$('#saveDevice').on('click', function () {
			addDeviceFnt();
		});

		// 삭제 버튼
		$('#deleteDevice').on('click', function () {
			deleteDeviceFnt();
		});


		$('.insertBtn').on('click', function(){
			var ipt = $('.mdl-data-table__cell--non-numeric .form-control');
			var form = $('#addForm');
			if(form.css('display') == 'none') {
				form.css('display', 'flex');
				ipt.css('opacity', '1');
			}else{
				form.css('display', 'none');
				ipt.css('opacity', '0');
				fromReset();
			}
		});
		
		
		getList();


	});


	//메뉴 Tree onClick
	function onClick(event, treeId, treeNode, clickFlag) {
		$('input:checkbox[name=sm_seq]').prop("checked", false);
		var zTree = $.fn.zTree.getZTreeObj("tree");
		var node = zTree.getNodeByParam('id', treeNode.pId);
		if (treeNode.checked) {
			$.post("/gplcs/dshow", {
					org_seq: treeNode.id
				},
				function (result) {
					var agrs = result;
					var ppm_seq = agrs.dataInfo.ppm_seq;
					ppm_seq = ppm_seq.split(",");
					for (var i = 0; i < ppm_seq.length; i++) {
						$('input:checkbox[name=sm_seq]').each(function () {
							if ($(this).val() == ppm_seq[i]) {
								$(this).prop("checked", true);
							}
						});
					}


					$('form[name=frm] input[name=org_seq]').val(agrs.dataInfo.org_seq);
					$('form[name=frm] input[name=pOrgNm]').val(agrs.pOrgNm);
				});
		}
	}

	function onCheck(event, treeId, treeNode) {
		$('input:checkbox[name=sm_seq]').prop("checked", false);
		var zTree = $.fn.zTree.getZTreeObj("tree");
		var node = zTree.getNodeByParam('id', treeNode.pId);
		if (treeNode.checked) {
			$.post("/gplcs/dshow", {
					org_seq: treeNode.id
				},
				function (result) {
					var agrs = result;
					var ppm_seq = agrs.dataInfo.ppm_seq;
					ppm_seq = ppm_seq.split(",");
					for (var i = 0; i < ppm_seq.length; i++) {
						$('input:checkbox[name=sm_seq]').each(function () {
							if ($(this).val() == ppm_seq[i]) {
								$(this).prop("checked", true);
							}
						});
					}


					$('form[name=frm] input[name=org_seq]').val(agrs.dataInfo.org_seq);
					$('form[name=frm] input[name=pOrgNm]').val(agrs.pOrgNm);


				});
		}

	}

	function beforeClick(treeId, treeNode, clickFlag) {
		var zTree = $.fn.zTree.getZTreeObj("tree");
		zTree.checkNode(treeNode, !treeNode.checked, true, true);
		return true;
	}
</script>

<section class="scrollable">
	<section class="hbox stretch">
		<!-- body left Start  -->
		<%@ include file="../template/orgTree.jsp" %>
		<!-- body left End  -->


		<!-- body right -->
		<aside class="bg-white">
			<section class="vbox">
				<section class="scrollable padder">

					<section class="panel panel-default">

						<header class="bg-dark dk header navbar navbar-fixed-top-xs">
							<ul class="nav navbar-nav hidden-xs">
								<li>
									<div class="m-t m-l">
										# 디바이스관리
									</div>
								</li>
							</ul>

							<ul class="nav navbar-nav navbar-right m-n hidden-xs nav-user">

								<li class="hidden-xs ">
									<a href="javascript:firewallMngrOpen();" data-toggle="dropdown"
										data-target="#firewallLayer">
										<!-- <i class="fa fa-bell"></i> -->
										디바이스 추가
										<!-- <span class="badge badge-sm up bg-danger m-l-n-sm count" style="display: inline-block;">방화벽추가</span> -->
									</a>

									<div id="firewallLayer" class="dropup">
										<section class="dropdown-menu on aside-md m-l-n"
											style="width:800px; height: 700px; top: 0;">
											<section class="panel bg-white">
												<header class="panel-heading b-b b-light">디바이스 관리</header>

												<div class="panel-body animated fadeInRight">

													<form id="addForm" class="form-inline col-md-12 row" action="" style="display:none;">
														<input id="sma_gubun" name="sma_gubun" type="hidden" value="Y">
														<input id="sm_device_code" name="sm_device_code" type="hidden" value="">
														<div class="well m-t">
															<div class="col-xs-12">
																<div class="form-group pull-in clearfix">
																	<div class="col-sm-4">
																		<label>* 디바이스 이름</label>
																		<input id="sm_name" name="sm_name" type="text" class="form-control parsley-validated" maxlength="20" placeholder="디바이스 이름" />
																	</div>
																	<div class="col-sm-4">
																		<label>* Vendor ID</label>
																		<input id="vendor_id" name="vendor_id" type="text" class="form-control parsley-validated" maxlength="4" placeholder="Vendor ID" />
																	</div>
																	<div class="col-sm-4">
																		<label>* Product ID</label>
																		<input id="product_id" name="product_id" type="text" class="form-control parsley-validated" maxlength="4" placeholder="Product ID" />
																	</div>
																	
																</div>
																<div class="form-group pull-in clearfix">
																	<div class="col-sm-8">
																		<input id="sm_dc" name="sm_dc" type="text" class="form-control parsley-validated" maxlength="30" placeholder="디바이스에 대한 상세 설명을 입력해주세요."  style="width: 539px;"/>
																	</div>
																	<button class="btn btn-info pull-right btn-sm" id="saveDevice">디바이스 규칙 추가</button>
																</div>
															</div>
															<footer class="panel-footer " style="border-top: 0;">
															</footer>
														</div>
													</form>
													<input type="hidden" id="MngeListInfoCurrentPage"
														name="MngeListInfoCurrentPage" value="1" />
												</div>


												<div class="panel-body animated fadeInRight">
													<!-- <p class="text-sm">No active chats.</p> -->
													<!-- <p><a href="#" class="btn btn-sm btn-default">Start a chat</a></p> -->

													<table class="table table-striped m-b-none ">
														<colgroup>
															<col style="width:10%;" />
															<col style="width:10%;" />
															<col style="width:35%;" />
															<col style="width:35%;" />
															<col />
														</colgroup>
														<thead>
															<tr>
																<th></th>
																<th>번호</th>
																<th>디바이스</th>
																<th>VendorId</th>
																<th>ProductId</th>
																<th>설명</th>
															</tr>
														</thead>

														<tbody id="pageGrideInMngrListTb"></tbody>
													</table>
													<div class="dataTables_wrapper">
														<!-- page number -->
														<div class="page_num" id="page_num"></div>
													</div>
												</div>

												<button type="button" class="btn_type3" id="deleteDevice">삭제</button>
												<button type="button" class="btn_type2 insertBtn">디바이스 추가</button>
											</section>
										</section>
									</div>
								</li>
							</ul>

						</header>


						<section class="panel panel-default">

							<form name="frm" method="post" action="orgManage" class="row">
								<input type="hidden" name="org_seq" id="org_seq" value="" />
								<input type="hidden" name="ppm_seq" id="ppm_seq" value="" />
								<input type="hidden" name="section" id="section" value="" />

								<!-- update list -->
								<ul class="promlist">
									<c:forEach items="${pList}" var="data" varStatus="status">
										<li>
											<div class="form-check">
												<input class="form-check-input" type="checkbox" name="sm_seq"
													id="${data.sm_seq}" value="<c:out value=" ${data.sm_seq}" />"
												id="${data.sm_seq}">
												<label class="form-check-label" for="${data.sm_seq}">
													<c:out value="${data.sm_name}" />
												</label>
											</div>

											<p class="card-text">
												<c:out value="${data.sm_dc}" />
											</p>
										</li>
									</c:forEach>
								</ul>

							</form>

						</section>

						</div>
						<div class="right mT20">
							<button type="reset" class="btn_type2" id="btnInit"> 초기화</button>
							<button type="button" class="btn_type2" id="btnSave"> 저장</button>
						</div>
					</section>
				</section>
		</aside>


	</section>
</section>


<script>
	//등록 처리결과(공통명 : 프로그램명Json )
	function fnSaveDeviceMange() {
		var button = document.getElementById('btnSave');

		if (confirm("하위부문 및 부서가 있다면 하위부문 및 부서에도 전부 적용됩니다 적용하시겠습니까?")) {
			var ppm_seq = "";
			$('input:checkbox[name=sm_seq]').each(function (i) {
				if ($(this).is(':checked'))
					ppm_seq += ($(this).val()) + ",";
			});
			ppm_seq = ppm_seq.substr(0, ppm_seq.length - 1);
			if (ppm_seq == "") {
				ppm_seq = 0;
			}

			var zTree = $.fn.zTree.getZTreeObj("tree");
			var nodes = zTree.getCheckedNodes(true);
			var nodeLength = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
			var queryArr = [];

			$.each(zTree.transformToArray(zTree.getNodes()) && nodes, function (i, v) {
				if (i >= 0) {
					if (v.children != null)
						nodeLength[v.level] = 0;
					nodeLength[eval(v.level - 1)]++;
					var data = {
						"org_seq": v.id
					}

					queryArr.push(data);
				}
			})

			button.disabled = true;

			$.post("/gplcs/dsave", {
					dataType: 'json',
					ppm_seq: ppm_seq,
					data: JSON.stringify(queryArr)
				},
				function (result) {
					if (result == "SUCCESS") {
						alert("정상적으로  처리되었습니다.");
						button.disabled = false;

						location.reload();
					} else {
						alert("실패하였습니다.");
						button.disabled = false;
					}
				});

			return false;
		}
	}

	function fnManage() {
		$("#popup").show();
		$("#bg_fix").show();

	}

	// 입력폼 초기화
	function fromReset() {
		$('#sm_name').val('');
		$('#sm_dc').val('');
		$('#sm_port').val('');
		$('#vendor_id').val('');
		$('#product_id').val('');
	}

	function getList() {
		var url = '/gplcs/dManagePopList';

		var keyWord = $("select[name=keyWord]").val();
		var vData = 'MngeListInfoCurrentPage=' + $("#MngeListInfoCurrentPage").val() + "&keyWord=" + keyWord +
			"&txtSearch=" + $("#txtSearch").val();
		callAjax('POST', url, vData, deviceGetSuccess, getError, 'json');
	}

	function getListAddDeleteVer() {
		var url = '/gplcs/dManagePopList';

		var keyWord = $("select[name=keyWord]").val();
		var vData = 'MngeListInfoCurrentPage=' + $("#MngeListInfoCurrentPage").val() + "&keyWord=" + keyWord +
			"&txtSearch=" + $("#txtSearch").val();

		function fnt(data, status, xhr, groupId) {
			deviceGetSuccess(data, status, xhr, groupId);
			$('.mdl-data-table__cell--non-numeric .form-control').css('opacity', '1');
		}

		callAjax('POST', url, vData, fnt, getError, 'json');
	}

	// 신규 디바이스 규칙 등록 버튼
	function addDeviceFnt() {
		event.preventDefault();
		var name = $('#sm_name').val();
		var info = $('#sm_dc').val();
		var vendor = $('#vendor_id').val();
		var product = $('#product_id').val();
		var regExp = /^[a-z0-9_]{4}$/;
		var regExpName = /^[ㄱ-ㅎ가-힣a-zA-Z0-9_]*$/;

		$('#sm_device_code').val($('#vendor_id').val() + ":" + $('#product_id').val());

		
		// 검증
		if (name.length <= 0) {
			alert('디바이스명을 입력해 주세요!');
			// $("#firewallLayer").addClass("open");
			$('#sm_name').focus();
			return false;
		} else {
			if (!regExpName.test(name)) {
				alert('디바이스 이름에는 공백을 제외한 문자, 숫자, 특수문자는 "_"만 이용가능합니다(20자 내)');
				$('#sm_dc').focus();
				return false;
			}
		}

		// if (info.length <= 0) {
		// 	$('#sm_dc').focus();
		// 	alert('비고 입력해 주세요!');
		// 	return false;
		// }


		if (!regExp.test(vendor)) {
			alert('vendorId는 4자리로된 영문 소문자, 숫자로 이루어진 코드입니다. 다시 확인해주세요!');
			$('#vendor_id').focus();
			return false;
		}

		if (!regExp.test(product)) {
			alert('productId는 4자리로된 영문 소문자, 숫자로 이루어진 코드입니다. 다시 확인해주세요!');
			$('#product_id').focus();
			return false;
		}

		// 전송
		$.ajax({
			url: '/gplcs/dManagePopSave',
			type: 'POST',
			data: $('#addForm').serialize(),
			success: function (res) {
				if (res.success == true) {
					alert("등록되었습니다.");
					getListAddDeleteVer();
					fromReset();
					location.reload();

				} else {
					alert("등록되지 않았습니다.");
					$.alert({
						title: 'Alert!',
						content: res.msg + '!',
					});
				}
			},
			error: function (request, status, error) {
				console.log("code:" + request.status + "\n" + "message:" + request.responseText + "\n" +
					"error:" + error);
			}
		});
	}


	// 삭제 버튼
	function deleteDeviceFnt() {
		var iptArr = $('.deviceCheck:checked');
		var addressArr = [];

		// 검증
		$.each(iptArr, function (idx, ipt) {
			addressArr.push($(ipt).parent().parent().attr('data-code'));
		});

		if (0 >= addressArr.length) {
			alert('삭제할 디바이스을 선택해 주시기 바랍니다!');
			return;
		}



		function ftn(data, status, xhr, groupId) {
			alert("삭제 되었습니다.");
			getListAddDeleteVer();
			fromReset();
			location.reload();

		}

		// 전송
		var url = '/gplcs/dManagePopDelete';
		var vData = "deleteList=" + addressArr;
		callAjax('POST', url, vData, ftn, getError, 'json');
	}

	function searchView(viewName, page) {
		switch (viewName) {
			case 'classMngrList':
				$("#MngeListInfoCurrentPage").val(page);
				getList();
				break; //	공지사항
			default:
		}
	}

	/*
	 * 이전 페이지
	 */
	function prevPage(viewName, currentPage) {
		var page = eval(currentPage) - 1;

		if (page < 1) {
			page = 1;
		}
		searchView(viewName, page);
	}

	/*
	 * 다음 페이지
	 */
	function nextPage(viewName, currentPage, totalPageSize) {
		var page = eval(currentPage) + 1;
		var totalPageSize = eval(totalPageSize);

		if (page > totalPageSize) {
			page = totalPageSize;
		}
		searchView(viewName, page);
	}

	var deviceGetSuccess = function (data, status, xhr, groupId) {
		var gbInnerHtml = "";
		var classGroupList = data.list;
		$('#pageGrideInMngrListTb').empty();

		if (data.list.length > 0) {
			$.each(data.list, function (index, value) {
				var no = data.pagingVo.totalRecordSize - (index) - ((data.pagingVo.currentPage - 1) * 5);
				console.log(no);
				var code = new Array();
				code = value.sm_device_code.split(":");
				console.log(code[0]);

				if (value.sm_dc == null)
					value.sm_dc = "설명이 없습니다"

				gbInnerHtml += "<tr data-code='" + value.sm_seq + "'>";
				gbInnerHtml += "<td class='t_left'>";
				if (value.ppm_seq == value.sm_seq) {
					gbInnerHtml += "<input type='checkbox' id=d" + no + " class='deviceCheck' disabled><label for=d" + no + " class='dook'></label></td>";
				} else {
					gbInnerHtml += "<input type='checkbox' id=d" + no + " class='deviceCheck'><label for=d" + no + " class='dook'></label></td>";
				}
				gbInnerHtml += "<td><span>" + no + "</span>";

				gbInnerHtml += "<td>" + value.sm_name + "</td>";
				gbInnerHtml += "<td>" + code[0] + "</td>";
				gbInnerHtml += "<td>" + code[1] + "</td>";
				gbInnerHtml += "<td>" + value.sm_dc + "</td>";
				gbInnerHtml += "</tr>";

			});
		} else {
			gbInnerHtml += "<tr><td colspan='4'>등록된 정보가 없습니다. </td></tr>";
		}

		startPage = data.pagingVo.startPage;
		endPage = data.pagingVo.endPage;
		totalPageSize = data.pagingVo.totalPageSize;
		currentPage = data.pagingVo.currentPage;
		totalRecordSize = data.pagingVo.totalRecordSize;

		console.log("startPage +++++ " + startPage);
		console.log("endPage +++++ " + endPage);
		console.log("totalPageSize +++++ " + totalPageSize);
		console.log("currentPage +++++ " + currentPage);
		console.log("totalRecordSize +++++ " + totalRecordSize);


		var viewName = 'classMngrList';
		if (totalRecordSize > 0) {
			$(".page_num").html(getPaging(startPage, endPage, totalPageSize, currentPage, '\'' + viewName + '\''));
		}
		$('#pageGrideInMngrListTb').append(gbInnerHtml);


	}
</script>


<%@ include file="../template/footer.jsp" %>