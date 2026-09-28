"""관리자(인가/RBAC) REST — 회원 권한 부여·회수 + IP 실차단.

접근 방식 두 가지
  ① 기계 호출(n8n·회수봇)  : 헤더  X-API-Key: <ADMIN_API_KEY>
  ② 사람(관리자 페이지)     : JWT(로그인 토큰) + 그 계정의 role == 관리자(2)
"""
from datetime import datetime, timedelta

from flask import Blueprint, current_app, g, jsonify, request

from extensions import db
from models import BlockedIP, Incident, Post, SecurityEvent, User
from models.user import ROLE_ADMIN, ROLE_GENERAL, ROLE_GOLD, ROLE_LABELS

from .rbac import admin_required

admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')

ROLE_NAME_TO_INT = {'user': ROLE_GENERAL, 'gold': ROLE_GOLD, 'admin': ROLE_ADMIN}


def _parse_role(value):
    """'user'/'gold'/'admin' 또는 0/1/2 문자열·숫자를 등급 정수로 변환한다. 실패 시 None."""
    if value is None:
        return None
    if isinstance(value, str) and value in ROLE_NAME_TO_INT:
        return ROLE_NAME_TO_INT[value]
    try:
        as_int = int(value)
    except (TypeError, ValueError):
        return None
    return as_int if as_int in ROLE_LABELS else None


# ----------------- 관리자 전용 회원 관리 API -----------------
@admin_bp.route('/users', methods=['GET'])
@admin_required
def admin_list_users():
    query = User.query
    role_param = request.args.get('role')
    if role_param is not None:
        parsed = _parse_role(role_param)
        if parsed is None:
            return jsonify({"msg": "role 은 user/gold/admin(또는 0/1/2) 중 하나여야 합니다."}), 400
        query = query.filter(User.role == parsed)
    users = query.order_by(User.id.asc()).all()
    return jsonify({"users": [u.to_dict() for u in users]}), 200


@admin_bp.route('/violations', methods=['GET'])
@admin_required
def admin_violations():
    """허용목록(ADMIN_ALLOWLIST) 밖의 admin — 과잉권한 후보 목록."""
    allowlist = current_app.config.get('ADMIN_ALLOWLIST', set())
    admins = User.query.filter_by(role=ROLE_ADMIN).order_by(User.id.asc()).all()
    violators = [u for u in admins if u.username not in allowlist]
    return jsonify({"violations": [u.to_dict() for u in violators]}), 200


@admin_bp.route('/grant', methods=['POST'])
@admin_required
def admin_grant():
    data = request.get_json(silent=True) or {}
    username = data.get('username')
    if not username:
        return jsonify({"msg": "username 이 필요합니다."}), 400

    new_role = _parse_role(data.get('role', 'admin'))
    if new_role is None:
        return jsonify({"msg": "role 은 user/gold/admin(또는 0/1/2) 중 하나여야 합니다."}), 400

    target = User.query.filter_by(username=username).first()
    if not target:
        return jsonify({"msg": "사용자를 찾을 수 없습니다."}), 404

    old_role = target.role
    target.role = new_role
    target.role_granted_by = g.get('admin_actor', 'apikey')
    target.role_granted_at = datetime.utcnow()
    target.role_reason = (data.get('reason') or None)
    db.session.commit()

    return jsonify({
        "msg": "권한이 부여되었습니다.",
        "username": target.username,
        "old_role": old_role,
        "new_role": new_role,
    }), 200


@admin_bp.route('/lock', methods=['POST'])
@admin_required
def admin_lock_account():
    """계정 잠금(브루트포스 대응) → is_locked=True. n8n 이 호출.
    body: {username, reason, student, src_ip, fail_count, severity}
    잠금이 실제로 일어나면 security_events 에 감사기록(source='login-guard')을 남긴다."""
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    if not username:
        return jsonify({"msg": "username 은 필수입니다."}), 400
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"msg": f"없는 사용자: {username}"}), 404

    actor = g.get('admin_actor', 'apikey')
    if user.is_locked:
        return jsonify({"msg": "이미 잠긴 계정", "username": username,
                        "locked": True, "changed": False}), 200

    reason = (data.get('reason') or f'브루트포스 자동 잠금 by {actor}')[:200]
    user.is_locked = True
    user.locked_at = datetime.utcnow()
    user.lock_reason = reason
    event = SecurityEvent(
        student=str(data.get('student') or actor)[:80],
        src_ip=str(data.get('src_ip') or '0.0.0.0')[:45],
        decision='deny',
        severity=(data.get('severity') or 'High'),
        reason=f'계정 잠금: {username} ({reason})'[:255],
        rule='login-bruteforce',
        source=(data.get('source') or 'login-guard'),
        fail_count=int(data.get('fail_count') or 0),
    )
    db.session.add(event)
    db.session.commit()
    return jsonify({"msg": "계정 잠금 완료", "username": username, "locked": True,
                    "changed": True, "event_id": event.id, "locked_by": actor}), 200


@admin_bp.route('/unlock', methods=['POST'])
@admin_required
def admin_unlock_account():
    """계정 잠금 해제 → is_locked=False + 실패 카운트 초기화. body: {username}"""
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    if not username:
        return jsonify({"msg": "username 은 필수입니다."}), 400
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"msg": f"없는 사용자: {username}"}), 404

    user.is_locked = False
    user.failed_logins = 0
    user.lock_reason = None
    db.session.commit()
    return jsonify({"msg": "잠금 해제 완료", "username": username, "locked": False,
                    "unlocked_by": g.get('admin_actor', 'apikey')}), 200


@admin_bp.route('/revoke', methods=['POST'])
@admin_required
def admin_revoke():
    """과잉권한 admin 을 user 로 되돌린다 (멱등: 이미 admin 이 아니면 조용히 통과)."""
    data = request.get_json(silent=True) or {}
    username = data.get('username')
    if not username:
        return jsonify({"msg": "username 이 필요합니다."}), 400

    target = User.query.filter_by(username=username).first()
    if not target:
        return jsonify({"msg": "사용자를 찾을 수 없습니다."}), 404

    old_role = target.role
    actor = g.get('admin_actor', 'apikey')

    if old_role != ROLE_ADMIN:
        return jsonify({
            "msg": "회수 완료",
            "username": target.username,
            "old_role": old_role,
            "new_role": old_role,
            "revoked": False,
            "revoked_by": actor,
        }), 200

    reason = (data.get('reason') or '과잉권한 자동회수')[:200]
    target.role = ROLE_GENERAL
    target.role_granted_by = actor
    target.role_granted_at = datetime.utcnow()
    target.role_reason = reason
    db.session.commit()

    event = SecurityEvent(
        student=str(data.get('student') or username)[:80],
        src_ip=str(data.get('src_ip') or '0.0.0.0')[:45],
        decision='deny',
        severity=(data.get('severity') or 'High'),
        reason=reason[:255],
        rule='priv-unauthorized-admin',
        source='privilege-guard',
    )
    db.session.add(event)
    db.session.commit()

    return jsonify({
        "msg": "회수 완료",
        "username": target.username,
        "old_role": old_role,
        "new_role": target.role,
        "revoked": True,
        "event_id": event.id,
        "revoked_by": actor,
    }), 200


@admin_bp.route('/users/<int:id>', methods=['PUT'])
@admin_required
def admin_update_user(id):
    target = User.query.get_or_404(id)
    data = request.get_json() or {}

    if 'username' in data and data['username']:
        new_username = data['username']
        dup = User.query.filter(User.username == new_username, User.id != id).first()
        if dup:
            return jsonify({"msg": "이미 존재하는 아이디입니다."}), 400
        target.username = new_username

    if 'role' in data:
        try:
            new_role = int(data['role'])
        except (TypeError, ValueError):
            return jsonify({"msg": "role 값이 올바르지 않습니다."}), 400
        if new_role not in ROLE_LABELS:
            return jsonify({"msg": "role 은 0(일반)/1(골드)/2(관리자) 중 하나여야 합니다."}), 400
        target.role = new_role

    db.session.commit()
    return jsonify({"msg": "회원 정보가 수정되었습니다.", "user": target.to_dict()}), 200


@admin_bp.route('/users/<int:id>', methods=['DELETE'])
@admin_required
def admin_delete_user(id):
    # g.admin_actor 는 사람(JWT)일 때만 실제 username 이고, 기계(X-API-Key)일 땐 'apikey' 이다.
    actor_username = g.get('admin_actor')
    if actor_username and actor_username != 'apikey':
        actor = User.query.filter_by(username=actor_username).first()
        if actor and actor.id == id:
            return jsonify({"msg": "본인 계정은 관리자 페이지에서 삭제할 수 없습니다."}), 400

    target = User.query.get_or_404(id)
    # 해당 유저가 작성한 게시글도 함께 정리한다. (author_id 외래키 제약)
    Post.query.filter_by(author_id=target.id).delete()
    db.session.delete(target)
    db.session.commit()
    return jsonify({"msg": "회원이 삭제되었습니다."}), 200


# ----------------- IP 차단(Active Response) API -----------------
@admin_bp.route('/block', methods=['POST'])
@admin_required
def admin_block_ip():
    """공격 IP 실차단 → blocked_ips 에 추가. n8n 이 호출.
    body: {ip, reason, student, severity}. 이후 그 IP 요청은 미들웨어가 403(관리자 API 제외)."""
    data = request.get_json(silent=True) or {}
    ip = (data.get('ip') or data.get('src_ip') or '').strip()
    if not ip:
        return jsonify({"msg": "ip(또는 src_ip) 는 필수입니다."}), 400
    actor = g.get('admin_actor', 'apikey')

    if not db.session.get(BlockedIP, ip):
        db.session.add(BlockedIP(ip=ip, reason=(data.get('reason') or f'자동 차단 by {actor}')[:200],
                                 blocked_by=actor))
        event = SecurityEvent(
            student=str(data.get('student') or actor)[:80],
            src_ip=ip,
            decision='deny',
            severity=(data.get('severity') or 'High'),
            reason=(data.get('reason') or f'IP 실차단: {ip}')[:255],
            rule='ip-block',
            source=(data.get('source') or 'ip-guard'),
            fail_count=int(data.get('fail_count') or 0),
        )
        db.session.add(event)
        db.session.commit()
        return jsonify({"msg": "IP 차단 완료", "ip": ip, "blocked": True,
                        "changed": True, "event_id": event.id, "blocked_by": actor}), 200
    return jsonify({"msg": "이미 차단된 IP", "ip": ip, "blocked": True, "changed": False}), 200


@admin_bp.route('/unblock', methods=['POST'])
@admin_required
def admin_unblock_ip():
    """IP 차단 해제. body: {ip}"""
    data = request.get_json(silent=True) or {}
    ip = (data.get('ip') or data.get('src_ip') or '').strip()
    if not ip:
        return jsonify({"msg": "ip 는 필수입니다."}), 400
    row = db.session.get(BlockedIP, ip)
    if row:
        db.session.delete(row)
        db.session.commit()
    return jsonify({"msg": "차단 해제 완료", "ip": ip, "blocked": False,
                    "unblocked_by": g.get('admin_actor', 'apikey')}), 200


@admin_bp.route('/blocked', methods=['GET'])
@admin_required
def admin_list_blocked():
    """차단된 IP 목록."""
    rows = BlockedIP.query.order_by(BlockedIP.blocked_at.desc()).all()
    return jsonify({"count": len(rows), "blocked": [r.to_dict() for r in rows]}), 200


# ----------------- 인시던트(Incident) 티켓 API -----------------
_SEV_RANK = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}


def _build_incident_summary(src_ip, events):
    """security_events 를 사람이 읽는 인시던트 요약(타임라인·집계·조치)으로 취합."""
    by_source, actions = {}, set()
    worst = 'Low'
    lines = []
    for e in events:
        by_source[e.source] = by_source.get(e.source, 0) + 1
        if e.decision:
            actions.add(e.decision)
        if _SEV_RANK.get(e.severity, 1) > _SEV_RANK.get(worst, 1):
            worst = e.severity
        when = e.created_at.strftime('%Y-%m-%d %H:%M:%S') if e.created_at else '?'
        lines.append(f"- {when} [{e.severity}/{e.source}] {e.reason or ''}")
    first = events[-1].created_at if events else None
    last = events[0].created_at if events else None
    src_summary = ', '.join(f'{k}×{v}' for k, v in sorted(by_source.items()))
    summary = (
        f"[인시던트 요약] 출발지 {src_ip}\n"
        f"- 관련 이벤트: {len(events)}건 ({src_summary})\n"
        f"- 최초/최종: {first} ~ {last}\n"
        f"- 취해진 조치: {', '.join(sorted(actions)) or '없음'}\n"
        f"- 최고 심각도: {worst}\n"
        f"[타임라인]\n" + "\n".join(lines[:20])
    )
    return summary, worst, (', '.join(sorted(actions)) or '없음'), len(events)


@admin_bp.route('/incident', methods=['POST'])
@admin_required
def admin_create_incident():
    """인시던트 티켓 생성/갱신. body: {src_ip, title?, severity?, student?, hours?}

    같은 src_ip 의 '열린' 티켓이 있으면 갱신(중복 방지), 없으면 새로 만든다.
    요약은 최근 hours(기본 24) 시간의 security_events 를 자동 취합한다."""
    data = request.get_json(silent=True) or {}
    src_ip = (data.get('src_ip') or data.get('ip') or '').strip()
    if not src_ip:
        return jsonify({"msg": "src_ip 는 필수입니다."}), 400
    actor = g.get('admin_actor', 'apikey')
    hours = int(data.get('hours') or 24)
    since = datetime.utcnow() - timedelta(hours=hours)

    last_closed = (Incident.query
                   .filter(Incident.src_ip == src_ip, Incident.status == 'closed',
                           Incident.closed_at.isnot(None))
                   .order_by(Incident.closed_at.desc()).first())
    if last_closed and last_closed.closed_at > since:
        since = last_closed.closed_at

    events = (SecurityEvent.query
              .filter(SecurityEvent.src_ip == src_ip, SecurityEvent.created_at >= since)
              .order_by(SecurityEvent.created_at.desc()).all())
    summary, worst, actions, cnt = _build_incident_summary(src_ip, events)
    severity = data.get('severity') or worst
    title = (data.get('title') or f'보안 인시던트: {src_ip} ({cnt}건)')[:200]

    inc = Incident.query.filter_by(src_ip=src_ip, status='open').first()
    created = False
    if not inc:
        inc = Incident(src_ip=src_ip, status='open', title=title)
        db.session.add(inc)
        created = True
    inc.title = title
    # 심각도는 내려가지 않는다: 요청값·취합 최고값·기존 티켓 값 중 가장 높은 것
    inc.severity = max((severity, worst, inc.severity or 'Low'),
                       key=lambda s: _SEV_RANK.get(s, 0))
    inc.summary = summary
    inc.event_count = cnt
    inc.actions = actions[:255]
    inc.student = (data.get('student') or actor)[:50]
    db.session.commit()
    return jsonify({"msg": "인시던트 생성" if created else "인시던트 갱신",
                    "created": created, "incident": inc.to_dict()}), (201 if created else 200)


@admin_bp.route('/incidents', methods=['GET'])
@admin_required
def admin_list_incidents():
    """인시던트 목록. ?status=open|closed 로 필터."""
    status = request.args.get('status')
    query = Incident.query
    if status in ('open', 'closed'):
        query = query.filter_by(status=status)
    rows = query.order_by(Incident.updated_at.desc()).all()
    return jsonify({"count": len(rows), "incidents": [r.to_dict() for r in rows]}), 200


@admin_bp.route('/incident/close', methods=['POST'])
@admin_required
def admin_close_incident():
    """인시던트 종료(status=closed). body: {id}"""
    data = request.get_json(silent=True) or {}
    inc = db.session.get(Incident, int(data.get('id') or 0))
    if not inc:
        return jsonify({"msg": "없는 인시던트"}), 404
    inc.status = 'closed'
    inc.closed_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"msg": "인시던트 종료", "incident": inc.to_dict()}), 200
