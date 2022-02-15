package com.model;

import java.sql.Timestamp;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.validation.constraints.Size;

import org.hibernate.annotations.Comment;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
@Entity
@Table(name="tbl_updt_agent_job")
public class AgentJobUpdt {

	@Size(max=50)
	private String domain;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Comment("시리얼넘버")
	private Long seq;

	@Comment("작업번호")
	private Integer pu_seq;

	@Comment("부서번호")
	private Long org_seq;

	@Comment("업데이트 관리번호")
	private Integer updt_ap_seq;
	
	@Size(max=100)
	@Comment("pc 관리번호")
	private String pcm_uuid;

	@Size(max=100)
	@Comment("프로그램명")
	private String pcm_name;

	@Size(max=10)
	@Comment("상태값")
	private String status;

	private Timestamp rgstr_date;
	private Timestamp updt_date;

}
