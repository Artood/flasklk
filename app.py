from flask import Flask, render_template, request, redirect, url_for, flash
from elasticsearch import Elasticsearch
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Секретный ключ для flash-сообщений

# Подключение к Elasticsearch
es = Elasticsearch("http://localhost:64298")

def format_index_name(index_name):
    """
    Форматирует название индекса в формате "Данные за 13.01.2025".
    Если формат не совпадает, возвращает оригинальное название.
    """
    try:
        date_str = index_name.split("-")[-1]  # Извлекаем дату из названия индекса
        date = datetime.strptime(date_str, "%Y.%m.%d").strftime("%d.%m.%Y")
        return f"Данные за {date}"
    except ValueError:
        # Если формат не совпадает, возвращаем оригинальное название
        return index_name

# Главная страница с индексами
@app.route("/")
def index():
    try:
        # Получение списка индексов
        indices = es.cat.indices(format="json")
        
        # Фильтруем индексы, которые начинаются с "logstash"
        index_data = []
        for index in indices:
            if index['index'].startswith("logstash"):
                display_name = format_index_name(index['index'])  # Используем функцию
                index_data.append({
                    "name": index['index'],  # Оригинальное название индекса
                    "display_name": display_name  # Название для отображения
                })
        
        # Сортируем индексы по дате (от новых к старым)
        index_data.sort(key=lambda x: x['name'], reverse=True)
        
    except Exception as e:
        index_data = []
        print(f"Ошибка при получении индексов: {e}")

    return render_template("index.html", indices=index_data)

# Удаление индекса
@app.route("/delete_index/<index>", methods=["POST"])
def delete_index(index):
    try:
        # Удаление индекса
        es.indices.delete(index=index)  # Передаём только имя индекса
        flash(f"Индекс {index} успешно удалён.", "success")
    except Exception as e:
        flash(f"Ошибка при удалении индекса {index}: {e}", "error")
    return redirect(url_for("index"))

# Страница для отображения логов определённого индекса
@app.route("/logs/<index>")
def logs(index):
    try:
        display_name = format_index_name(index)
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        offset = (page - 1) * per_page

        response = es.search(
            index=index,
            body={
                "size": per_page,
                "from": offset,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "_source": [
                    "@timestamp", "host", "t-pot_ip_int", "os", "headers", "geoip_ext", "subject", "mod", "tags",
                    "path", "params", "t-pot_customer", "dist", "@version", "dest_port", "geoip", "t-pot_hostname",
                    "t-pot_ip_ext", "dest_ip", "src_ip", "src_port", "raw_sig", "type", "raw_mtu", "reason", "raw_hits",
                    "raw_freq", "uptime", "protocol", "timestamp", "fatt_tls", "dns_name", "dns_type", "dns_cls", "opcode",
                    "link", "request_method", "content_type", "http_user_agent", "http_host", "http_version", "http_accept",
                    "accept_encoding", "content_length", "connection", "ja3Algorithms", "ja3Version", "ja3EcFmt", "ja3",
                    "ja3Extensions", "serverName", "ja3Ciphers", "ja3Ec", "ja3sCiphers", "ja3sVersion", "ja3s", "ja3sExtensions",
                    "ja3sAlgorithms"
                ],
                "query": {
                    "bool": {
                        "must": [
                            {"wildcard": {"t-pot_hostname": "*sensor*"}},
                            {"match_all": {}}
                        ]
                    }
                }
            }
        )

        logs = []
        for hit in response['hits']['hits']:
            log_entry = hit['_source']
            log_data = {
                "timestamp": log_entry.get("@timestamp"),
                "host": log_entry.get("host"),
                "t_pot_ip_int": log_entry.get("t-pot_ip_int"),
                "os": log_entry.get("os"),
                "subject": log_entry.get("subject"),
                "mod": log_entry.get("mod"),
                "tags": log_entry.get("tags"),
                "path": log_entry.get("path"),
                "params": log_entry.get("params"),
                "t_pot_customer": log_entry.get("t-pot_customer"),
                "dist": log_entry.get("dist"),
                "version": log_entry.get("@version"),
                "dest_port": log_entry.get("dest_port"),
                "t_pot_hostname": log_entry.get("t-pot_hostname"),
                "t_pot_ip_ext": log_entry.get("t-pot_ip_ext"),
                "dest_ip": log_entry.get("dest_ip"),
                "src_ip": log_entry.get("src_ip"),
                "src_port": log_entry.get("src_port"),
                "raw_sig": log_entry.get("raw_sig"),
                "type": log_entry.get("type"),
                "raw_mtu": log_entry.get("raw_mtu"),
                "reason": log_entry.get("reason"),
                "raw_hits": log_entry.get("raw_hits"),
                "raw_freq": log_entry.get("raw_freq"),
                "uptime": log_entry.get("uptime"),
                "protocol": log_entry.get("protocol"),
                "timestamp_field": log_entry.get("timestamp"),
                "dns_name": log_entry.get("dns_name"),
                "dns_type": log_entry.get("dns_type"),
                "dns_cls": log_entry.get("dns_cls"),
                "opcode": log_entry.get("opcode"),
                "link": log_entry.get("link"),
                "request_method": log_entry.get("request_method"),
                "content_type": log_entry.get("content_type"),
                "http_user_agent": log_entry.get("http_user_agent"),
                "http_host": log_entry.get("http_host"),
                "http_version": log_entry.get("http_version"),
                "http_accept": log_entry.get("http_accept"),
                "accept_encoding": log_entry.get("accept_encoding"),
                "content_length": log_entry.get("content_length"),
                "connection": log_entry.get("connection"),
                "ja3Algorithms": log_entry.get("ja3Algorithms"),
                "ja3Version": log_entry.get("ja3Version"),
                "ja3EcFmt": log_entry.get("ja3EcFmt"),
                "ja3": log_entry.get("ja3"),
                "ja3Extensions": log_entry.get("ja3Extensions"),
                "serverName": log_entry.get("serverName"),
                "ja3Ciphers": log_entry.get("ja3Ciphers"),
                "ja3Ec": log_entry.get("ja3Ec"),
                "ja3sCiphers": log_entry.get("ja3sCiphers"),
                "ja3sVersion": log_entry.get("ja3sVersion"),
                "ja3s": log_entry.get("ja3s"),
                "ja3sExtensions": log_entry.get("ja3sExtensions"),
                "ja3sAlgorithms": log_entry.get("ja3sAlgorithms")
            }

            # Разворачиваем вложенные словари
            if log_entry.get("headers"):
                for key, value in log_entry["headers"].items():
                    log_data[f"headers_{key}"] = value

            if log_entry.get("geoip_ext"):
                for key, value in log_entry["geoip_ext"].items():
                    log_data[f"geoip_ext_{key}"] = value

            if log_entry.get("geoip"):
                for key, value in log_entry["geoip"].items():
                    log_data[f"geoip_{key}"] = value

            if log_entry.get("fatt_tls"):
                for key, value in log_entry["fatt_tls"].items():
                    log_data[f"fatt_tls_{key}"] = value

            logs.append(log_data)

        total_hits = response['hits']['total']['value']
        total_pages = (total_hits + per_page - 1) // per_page

    except Exception as e:
        logs = []
        total_pages = 1
        print(f"Ошибка при получении логов: {e}")

    return render_template(
        "logs.html",
        index=index,
        display_name=display_name,
        logs=logs,
        page=page,
        per_page=per_page,
        total_pages=total_pages
    )

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
