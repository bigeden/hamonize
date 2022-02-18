package com.model;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class CurlPcBackupVo {
	
	
	// db table====
	private int br_seq;
	private Long br_org_seq;
	private String br_backup_path;	// 백업 이미지 경로 및 iso 파일 이름
	private String br_backup_iso_dt;	// 백업실행일시
	private String br_backup_status; 	// 백업구분 A:초기백업본
	
	// pc get json ====
	private String bk_datetime;
	private String bk_uuid;
	private String bk_name;
	private String bk_dir; 
	private String bk_hostname;
	private Long pc_seq;

}