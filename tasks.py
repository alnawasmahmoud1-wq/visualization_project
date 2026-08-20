import json
import networkx as nx
import matplotlib.pyplot as plt
import pyshark  # مكتبة لتحليل ملفات pcap

# دالة لقراءة تقرير JSON
def load_report(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"⚠️ الملف {file_path} غير موجود.")
        return None

# دالة لاستخراج الـ IPs + Domains + URLs من التقرير
def extract_network_data(report):
    ips, domains, urls = [], [], []
    if report and "network" in report:
        if "hosts" in report["network"]:
            ips = report["network"]["hosts"]
        if "domains" in report["network"]:
            domains = [d["domain"] for d in report["network"]["domains"]]
        if "http" in report["network"]:
            urls = [h["uri"] for h in report["network"]["http"]]

    # فلترة الاتصالات الشرعية
    benign_ips = ["8.8.8.8", "1.1.1.1"]
    benign_domains = ["google.com", "microsoft.com"]
    ips = [ip for ip in ips if ip not in benign_ips]
    domains = [d for d in domains if d not in benign_domains]

    return ips, domains, urls

# دالة لاستخراج Registry Keys
def extract_registry(report):
    keys = []
    if report and "behavior" in report and "summary" in report["behavior"]:
        if "regkeys" in report["behavior"]["summary"]:
            keys = report["behavior"]["summary"]["regkeys"]
    return keys

# دالة لاستخراج File Hashes
def extract_hashes(report):
    hashes = []
    if report and "target" in report and "file" in report["target"]:
        file_info = report["target"]["file"]
        if "sha256" in file_info:
            hashes.append(file_info["sha256"])
        if "md5" in file_info:
            hashes.append(file_info["md5"])
    return hashes

# دالة لاستخراج العمليات
def extract_processes(report):
    processes = []
    if report and "behavior" in report and "processes" in report["behavior"]:
        processes = report["behavior"]["processes"]
    return processes

# دالة لقراءة dump.pcap واستخراج الاتصالات
def extract_from_pcap(pcap_file):
    ips = set()
    try:
        cap = pyshark.FileCapture(pcap_file, only_summaries=True)
        for pkt in cap:
            if hasattr(pkt, "src") and hasattr(pkt, "dst"):
                ips.add(pkt.src)
                ips.add(pkt.dst)
        cap.close()
    except Exception as e:
        print(f"⚠️ خطأ أثناء قراءة pcap: {e}")
    return list(ips)

# رسم شبكة الاتصالات
def draw_network(ips, domains, urls):
    if not ips and not domains and not urls:
        print("⚠️ لا يوجد بيانات شبكة لعرضها.")
        return
    G = nx.Graph()
    G.add_node("sample")
    for ip in ips:
        G.add_node(ip)
        G.add_edge("sample", ip)
    for d in domains:
        G.add_node(d)
        G.add_edge("sample", d)
    for u in urls:
        G.add_node(u)
        G.add_edge("sample", u)

    nx.draw(G, with_labels=True, node_color="lightblue", font_size=8)
    plt.title("Network Graph (IPs + Domains + URLs)")
    plt.show()

# رسم شجرة العمليات
def draw_process_tree(processes):
    if not processes:
        print("⚠️ لا يوجد عمليات لعرضها.")
        return
    PG = nx.DiGraph()
    for proc in processes:
        pname = proc.get("process_name", f"PID-{proc.get('pid')}")
        PG.add_node(pname)
        if "ppid" in proc:
            parent = f"PID-{proc['ppid']}"
            PG.add_edge(parent, pname)
    nx.draw(PG, with_labels=True, node_color="lightgreen", font_size=8)
    plt.title("Process Tree")
    plt.show()

# التشغيل الرئيسي
def main():
    file_path = input("📂 أدخل اسم ملف التقرير (مثال: report.json): ").strip()
    pcap_path = input("📂 أدخل اسم ملف pcap (مثال: dump.pcap أو اتركه فارغ): ").strip()

    report = load_report(file_path)
    if not report:
        return

    ips, domains, urls = extract_network_data(report)
    processes = extract_processes(report)
    regkeys = extract_registry(report)
    hashes = extract_hashes(report)

    # إذا فيه ملف pcap نضيف الاتصالات منه
    if pcap_path:
        pcap_ips = extract_from_pcap(pcap_path)
        ips.extend(pcap_ips)

    print("Extracted IPs:", ips)
    print("Extracted Domains:", domains)
    print("Extracted URLs:", urls)
    print("Extracted Processes:", [p.get("process_name") for p in processes])
    print("Extracted Registry Keys:", regkeys)
    print("Extracted File Hashes:", hashes)

    draw_network(ips, domains, urls)
    draw_process_tree(processes)

# مثال تشغيل
if __name__ == "__main__":
    main()
