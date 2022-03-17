package com.service;

import java.util.List;

import javax.naming.NamingException;
import javax.transaction.Transactional;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.GlobalPropertySource;
import com.mapper.IOrgMapper;
import com.mapper.IUserMapper;
import com.model.OrgVo;
import com.model.UserVo;
import com.util.LDAPConnection;
import com.util.SHA256Util;

@Service
@Transactional(rollbackOn = NamingException.class)
public class UserService {
	@Autowired
	GlobalPropertySource gs;

	@Autowired
	private IUserMapper userMapper;

	@Autowired
	private IOrgMapper orgMapper;

	private Logger logger = LoggerFactory.getLogger(this.getClass());

	public List<UserVo> userList(UserVo vo) {
		return userMapper.userList(vo);
	}

	public UserVo userView(UserVo vo) {
		return userMapper.userView(vo);
	}

	public int userSave(UserVo vo) throws NamingException {
		int result = 0;
		LDAPConnection con = new LDAPConnection();
		String dn = "";
		String tmp = "";
		String host = "";
		String pw = vo.getPass_wd();
		OrgVo ovo = new OrgVo();

		//vo.setGubun("A");
		vo.setPass_wd(SHA256Util.getEncrypt(vo.getPass_wd(), SHA256Util.generateSalt()));
		result = userMapper.userSave(vo);


		if (result == 1) {
			logger.info("db 저장 완료");
			ovo.setSeq(vo.getOrg_seq());
			ovo.setDomain(vo.getDomain());

			tmp = orgMapper.orgView(ovo).getAll_org_nm();

			String[] p_array = tmp.split("\\|");
			for (int i = p_array.length - 1; i >= 0; i--) {
				host += "." + p_array[i];
				dn += ",ou=" + p_array[i];
			}
			host = ".hamonize.com";
			con.connection(gs.getLdapUrl(), gs.getLdapPassword());
			vo.setPass_wd(pw);
			con.addUser(vo, dn, host);


		} else {
			logger.info("db 저장 실패");

		}

		return result;
	}

	public int userModify(UserVo newVo) throws NamingException {
		logger.info("=== userModify ===");
		int result = 0;
		String host = "";
		String oldDn = "";
		String newDn = "";
		String tmpPw = newVo.getPass_wd();

		OrgVo ovo = new OrgVo();
		UserVo oldVo = userMapper.getUserInfo(newVo.getSeq());
System.out.println("newVo==========="+newVo);
System.out.println("oldVo==========="+oldVo);
		LDAPConnection con = new LDAPConnection();
		con.connection(gs.getLdapUrl(), gs.getLdapPassword());
		ovo = userMapper.getUserOrgPath(newVo.getSeq());


		if (!oldVo.getOrg_seq().equals(newVo.getOrg_seq())) {
			OrgVo newOvo = userMapper.getUserNewOrgPath(newVo.getOrg_seq());

			String[] p_array = newOvo.getAll_org_nm().split("\\|");
			for (int i = p_array.length - 1; i >= 0; i--) {
				host += "." + p_array[i];
				newDn += ",ou=" + p_array[i];
			}
			host = ".hamonize.com";
		} else {
			String[] p_array = ovo.getAll_org_nm().split("\\|");
			for (int i = p_array.length - 1; i >= 0; i--) {
				host += "." + p_array[i];
			}
			host = ".hamonize.com";
		}

		String[] p_array = ovo.getAll_org_nm().split("\\|");
		for (int i = p_array.length - 1; i >= 0; i--) {
			oldDn += ",ou=" + p_array[i];
		}


		if (newVo.getPass_wd() != null || !newVo.getPass_wd().equals("")) {
			newVo.setPass_wd(SHA256Util.getEncrypt(newVo.getPass_wd(), SHA256Util.generateSalt()));
		}

		result = userMapper.userModify(newVo);

		if (result == 1) {
			newVo.setPass_wd(tmpPw);
			con.updateUser(oldVo, newVo, oldDn, newDn, host);

		} else {
			logger.debug("---수정 실패---");
		}

		return result;
	}

	public int userDelete(List<UserVo> vo) throws NamingException {

		LDAPConnection con = new LDAPConnection();
		con.connection(gs.getLdapUrl(), gs.getLdapPassword());

		for (int i = 0; i < vo.size(); i++) {
			OrgVo ovo = new OrgVo();
			UserVo uvo = new UserVo();

			ovo = userMapper.getUserOrgPath(vo.get(i).getSeq());
			// uvo = userMapper.userView(vo.get(i));
			uvo.setUser_id(vo.get(i).getUser_id());

			con.deleteUser(ovo, uvo);
		}

		int result = userMapper.userDelete(vo);

		if (result >= 1) {
			logger.info("삭제성공");
		} else {
			logger.info("삭제 실패");
		}

		return result;
	}

	public int userIdCheck(UserVo vo) {
		return userMapper.userIdCheck(vo);
	}

	public List<OrgVo> getOrgList(OrgVo vo) {
		return orgMapper.getTeamList(vo);
	};
	

	public OrgVo getOrgAuth(OrgVo vo) {
		return orgMapper.getOrgAuth(vo);
	};

}
