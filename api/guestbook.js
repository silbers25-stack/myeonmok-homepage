import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

export default async function handler(req, res) {
  setCors(res);

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  try {
    if (req.method === 'GET') {
      const { data, error } = await supabase
        .from('guestbook_posts')
        .select('id, name, message, created_at')
        .order('created_at', { ascending: false });

      if (error) {
        return res.status(500).json({ error: '게시글을 불러오지 못했습니다.' });
      }

      return res.status(200).json({ posts: data || [] });
    }

    if (req.method === 'POST') {
      const { name, password, message } = req.body || {};

      if (!name || !password || !message) {
        return res.status(400).json({ error: '이름, 비밀번호, 내용을 모두 입력해 주세요.' });
      }

      if (String(name).trim().length > 20) {
        return res.status(400).json({ error: '이름은 20자 이하로 입력해 주세요.' });
      }

      if (String(message).trim().length > 500) {
        return res.status(400).json({ error: '내용은 500자 이하로 입력해 주세요.' });
      }

      const password_hash = hashPassword(String(password).trim());

      const { error } = await supabase
        .from('guestbook_posts')
        .insert([
          {
            name: String(name).trim(),
            message: String(message).trim(),
            password_hash
          }
        ]);

      if (error) {
        return res.status(500).json({ error: '게시글을 저장하지 못했습니다.' });
      }

      return res.status(201).json({ ok: true });
    }

    if (req.method === 'DELETE') {
      const { id, password } = req.body || {};

      if (!id || !password) {
        return res.status(400).json({ error: '삭제에 필요한 정보가 없습니다.' });
      }

      const { data, error } = await supabase
        .from('guestbook_posts')
        .select('id, password_hash')
        .eq('id', id)
        .single();

      if (error || !data) {
        return res.status(404).json({ error: '게시글을 찾지 못했습니다.' });
      }

      const incomingHash = hashPassword(String(password).trim());

      if (incomingHash !== data.password_hash) {
        return res.status(403).json({ error: '비밀번호가 올바르지 않습니다.' });
      }

      const { error: deleteError } = await supabase
        .from('guestbook_posts')
        .delete()
        .eq('id', id);

      if (deleteError) {
        return res.status(500).json({ error: '게시글을 삭제하지 못했습니다.' });
      }

      return res.status(200).json({ ok: true });
    }

    return res.status(405).json({ error: '허용되지 않은 요청 방식입니다.' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
}
