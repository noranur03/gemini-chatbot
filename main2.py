import streamlit as st
import google.generativeai as genai
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY", "AIzaSyAS9ReMCGSnUVS9cOwTXM5bXp7oY4WXsXM"))

# Set page config
st.set_page_config(
    page_title="Norabot AI Chatbot",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Sidebar
with st.sidebar:
    st.title("🤖 Norabot - Kampus Merdeka")
    st.markdown("""
    **Apa itu Norabot?**  
    Norabot adalah aplikasi chatbot informasi tentang Kampus Merdeka yang memberikan penjelasan tentang pelaksanaan, persyaratan, dan program yang ada di Kampus Merdeka. Norabot adalah teman informasi kamu untuk segala hal terkait Kampus Merdeka!
    """)
    theme_choice = st.selectbox(
        "Pilih Tampilan",
        ["Light Mode", "Dark Mode"],
        index=0,
        key="theme_choice"
    )
    st.markdown("---")
    st.markdown("**Model Options**")
    model_name = st.selectbox("Pilih Model Gemini", ["models/gemini-1.5-flash", "models/gemini-1.5-pro"])
    temperature = st.slider("Kreativitas (Temperature)", 0.0, 1.0, 0.7)
    max_tokens = st.slider("Panjang Maksimum Jawaban", 100, 2000, 1000)
    st.markdown("---")
    st.markdown("Made with ❤️ using Norabot")

# CSS untuk tema
light_mode_css = """
    <style>
        .stApp { background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%); }
        .user-message { background-color: #4a8cff; color: white; }
        .bot-message { background-color: #ffffff; color: #333; }
    </style>
"""
dark_mode_css = """
    <style>
        .stApp { background: linear-gradient(135deg, #1e1e1e 0%, #2c2c2c 100%); color: white; }
        .user-message { background-color: #007acc; color: white; }
        .bot-message { background-color: #3a3a3a; color: white; }
        .stTextInput>div>div>input { background-color: #222; color: white; }
        .stButton>button { background-color: #007acc; color: white; }
        .stButton>button:hover { background-color: #005f99; }
    </style>
"""

# Terapkan CSS berdasarkan tema
st.markdown(dark_mode_css if st.session_state.theme_choice == "Dark Mode" else light_mode_css, unsafe_allow_html=True)

# Static knowledge base
kampus_merdeka_faq = {
    "Apa itu Kampus Merdeka?": "Kampus Merdeka adalah program dari Kementerian Pendidikan, Kebudayaan, Riset, dan Teknologi...",
    "Apa saja program yang ada di Kampus Merdeka?": "Beberapa program Kampus Merdeka antara lain Program Magang...",
    "Bagaimana cara mendaftar program Kampus Merdeka?": "Untuk mendaftar, mahasiswa bisa mengunjungi situs resmi...",
    "Siapa yang bisa mengikuti Kampus Merdeka?": "Program Kampus Merdeka terbuka untuk seluruh mahasiswa...",
    "Apa itu Norabot?": "Norabot adalah aplikasi chatbot informasi tentang Kampus Merdeka...",
    "Siapa yang menciptakan Norabot?": "Norabot diciptakan oleh Nora dari kelas 4IA10..."
}

# Chat history init
if "messages" not in st.session_state:
    st.session_state.messages = []

# Display chat messages
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# Response from Gemini or static
def get_gemini_response(prompt, model_name):
    model = genai.GenerativeModel(model_name)
    response = model.generate_content(
        prompt,
        generation_config={"temperature": temperature, "max_output_tokens": max_tokens}
    )
    return response.text

def get_kampus_merdeka_response(prompt):
    for q, a in kampus_merdeka_faq.items():
        if prompt.lower() == q.lower():
            return a
    return get_gemini_response(prompt, model_name)

# Chat input
if prompt := st.chat_input("Apa yang ingin Anda tanyakan tentang Kampus Merdeka?"):
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)
    with st.chat_message("assistant"):
        with st.spinner("Menghasilkan jawaban..."):
            try:
                response = get_kampus_merdeka_response(prompt)
                st.markdown(response)
                st.session_state.messages.append({"role": "assistant", "content": response})
            except Exception as e:
                st.error(f"Terjadi error: {str(e)}")
