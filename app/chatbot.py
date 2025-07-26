from flask import Blueprint, render_template, request, session, redirect, url_for, flash
from flask_login import login_required, current_user
import google.generativeai as genai
import uuid, os
from dotenv import load_dotenv
from .models import ChatRating, db, ChatMessage

load_dotenv()
genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))

chatbot = Blueprint('chatbot', __name__)

kampus_merdeka_faq = {
    "Apa itu Kampus Merdeka?": (
        "Kampus Merdeka adalah program dari Kementerian Pendidikan, Kebudayaan, Riset, dan Teknologi Republik Indonesia "
        "yang bertujuan memberikan kebebasan bagi mahasiswa untuk belajar di luar program studi dan kampus asal selama 1-2 semester, "
        "dengan tetap mendapatkan pengakuan SKS. Program ini bertujuan untuk memperkaya kompetensi mahasiswa sebelum lulus."
    ),

    "Apa saja program yang ada di Kampus Merdeka?": (
        "Program Kampus Merdeka meliputi: "
        "1) Magang / Praktik Kerja, "
        "2) Studi Independen Bersertifikat, "
        "3) Pertukaran Mahasiswa Merdeka, "
        "4) Kampus Mengajar, "
        "5) Proyek Kemanusiaan, "
        "6) Kegiatan Wirausaha, "
        "7) Penelitian / Riset, dan "
        "8) Membangun Desa (KKN Tematik)."
    ),

    "Bagaimana cara mendaftar program Kampus Merdeka?": (
        "Untuk mendaftar, mahasiswa perlu mengakses situs resmi Kampus Merdeka di https://kampusmerdeka.kemdikbud.go.id. "
        "Setelah login dengan akun mahasiswa, pilih program yang diinginkan dan ikuti prosedur pendaftarannya seperti mengisi formulir, "
        "mengunggah dokumen, dan menunggu hasil seleksi."
    ),

    "Siapa yang bisa mengikuti Kampus Merdeka?": (
        "Seluruh mahasiswa aktif dari perguruan tinggi di bawah naungan Kemdikbudristek, baik negeri maupun swasta, "
        "dapat mengikuti program Kampus Merdeka, dengan syarat minimal berada di semester 4 pada saat pelaksanaan program."
    ),

    "Apa manfaat mengikuti program Kampus Merdeka?": (
        "Manfaatnya antara lain: pengalaman langsung di dunia kerja, pengembangan soft skill, jejaring profesional, "
        "pengakuan SKS di luar prodi, serta peningkatan daya saing lulusan di dunia industri maupun masyarakat."
    ),

    "Apakah Kampus Merdeka berbayar?": (
        "Sebagian besar program Kampus Merdeka didanai oleh pemerintah, jadi tidak dikenakan biaya kepada mahasiswa. "
        "Namun, mahasiswa tetap perlu memperhatikan kebijakan masing-masing perguruan tinggi dan mitra penyelenggara."
    ),

    "Apakah program Kampus Merdeka diakui SKS-nya?": (
        "Ya, program Kampus Merdeka diakui hingga maksimal 20 SKS per semester, tergantung kebijakan kampus asal. "
        "Mahasiswa perlu memastikan kesesuaian mata kuliah dengan prodi melalui dosen pembimbing atau bagian akademik."
    ),

    "Apa itu Norabot?": (
        "Norabot adalah aplikasi chatbot yang dirancang untuk memberikan informasi seputar Kampus Merdeka secara otomatis dan interaktif. "
        "Pengguna bisa menanyakan hal-hal umum terkait program Kampus Merdeka dan akan dijawab oleh bot."
    ),

    "Siapa yang menciptakan Norabot?": (
        "Norabot diciptakan oleh Nora dari kelas 4IA10 sebagai bagian dari proyek tugas untuk membantu mahasiswa memahami informasi Kampus Merdeka dengan lebih mudah."
    )
}

def get_kampus_merdeka_response(prompt):
    for q, a in kampus_merdeka_faq.items():
        if prompt.strip().lower() == q.lower():
            return a
    model = genai.GenerativeModel('models/gemini-1.5-flash')
    response = model.generate_content(prompt)
    return response.text

@chatbot.before_app_request
def init_session():
    if 'messages' not in session:
        session['messages'] = []

@chatbot.route('/')
@login_required
def chat():
    messages = ChatMessage.query.filter_by(user_id=current_user.id).order_by(ChatMessage.timestamp.asc()).all()
    last_bot = next((msg for msg in reversed(messages) if msg.role == 'bot'), None)

    user_rated = None
    count_like = 0
    count_dislike = 0

    if last_bot:
        user_rated = ChatRating.query.filter_by(user_id=current_user.id, message_id=str(last_bot.id)).first()
        count_like = ChatRating.query.filter_by(message_id=str(last_bot.id), rating='like').count()
        count_dislike = ChatRating.query.filter_by(message_id=str(last_bot.id), rating='dislike').count()

    return render_template(
        'chat.html',
        messages=messages,
        last_bot=last_bot,
        user_rated=user_rated,
        count_like=count_like,
        count_dislike=count_dislike
    )

@chatbot.route('/ask', methods=['POST'])
@login_required
def ask():
    prompt = request.form['prompt']
    reply = get_kampus_merdeka_response(prompt)

    messages = session.get('messages', [])
    user_msg_id = str(uuid.uuid4())
    bot_msg_id = str(uuid.uuid4())

    messages.append({'id': user_msg_id, 'role': 'user', 'content': prompt})
    messages.append({'id': bot_msg_id, 'role': 'bot', 'content': reply})
    session['messages'] = messages

    db.session.add(ChatMessage(user_id=current_user.id, role='user', content=prompt))
    db.session.add(ChatMessage(user_id=current_user.id, role='bot', content=reply))
    db.session.commit()

    return redirect(url_for('chatbot.chat'))


@chatbot.route('/rate', methods=['POST'])
@login_required
def rate():
    message_id = request.form['message_id']
    rating_value = request.form['rating']
    new_rating = ChatRating(user_id=current_user.id, message_id=message_id, rating=rating_value)
    db.session.add(new_rating)
    db.session.commit()
    flash("Terima kasih atas feedbacknya!", "success")
    return redirect(url_for('chatbot.chat'))
