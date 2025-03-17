import shodan
import requests
import subprocess
import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog, ttk
import nmap
import os

#Configuració de Shodan
SHODAN_API_KEY = 'YhW7ljPPhww5c1rjSuQpIJXQ7DvH7Dj3'
api = shodan.Shodan(SHODAN_API_KEY)

#Configuració Telegram
TELEGRAM_TOKEN = "8114701599:AAHabWV59PTSs1qrJfs4wEw-mRk413G1vKM"
TELEGRAM_CHAT_ID = "-4670626649"
url_telegram = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"

#Funcions actualitzades de Shodan i Enum4Linux
def obtenir_informacio_ip_nou(ip, servei, text_widget):
    try:
        if servei:
            query = f'ip:{ip} {servei}'
            resultat_shodan = api.search(query)
            text_widget.insert(tk.END, f"Resultats de Shodan per IP: {ip} i servei: {servei}\n")
            for match in resultat_shodan['matches']:
                text_widget.insert(tk.END, f"IP: {match['ip_str']}\n")
                text_widget.insert(tk.END, f"Port: {match['port']}\n")
                text_widget.insert(tk.END, f"Servei: {match['product']}\n")
                text_widget.insert(tk.END, f"Dades: {match['data']}\n")
                text_widget.insert(tk.END, "-" * 30 + "\n")
        else:
            info = api.host(ip)
            result = f"Informació de l'host:\n- IP: {info.get('ip_str', 'No disponible')}\n"
            result += f"- Organització: {info.get('org', 'No disponible')}\n"
            result += f"- Ubicació: {info.get('city', 'No disponible')}, {info.get('country_name', 'No disponible')}\n"

            result += "\nDominis:\n"
            if 'hostnames' in info:
                for dominio in info['hostnames']:
                    result += f"- {dominio}\n"
            else:
                result += "- No es troben dominis.\n"

            result += "\nPorts oberts:\n"
            if 'ports' in info:
                for port in info['ports']:
                    result += f"- {port}\n"
            else:
                result += "- No es troben ports oberts.\n"

            text_widget.insert(tk.END, result)

    except shodan.APIError as e:
        messagebox.showerror("Error", f"Error al obtenir la informació de la IP: {e}")
        text_widget.insert(tk.END, f"Error: {e}\n")


def llançar_enum4linux(ip, text_widget):
    """
    Llança Enum4linux-ng contra una adreça IP.
    """

    text_widget.insert(tk.END, f"Executant Enum4Linux-ng per a {ip}...\n")

    if not ip:
        messagebox.showerror("Error", "L'adreça IP no pot estar buida.")
        return

    script_path = "/home/alumnat/Escriptori/PROJECTE/enum4linux-ng"

    if not os.path.exists(script_path):  #Comprova que existeixi
        messagebox.showerror("Error", f"enum4linux-ng no es troba a: {script_path}")
        return

    comanda = [script_path, ip]

    try:
        result = subprocess.run(comanda, capture_output=True, text=True, check=False, encoding='utf-8', errors='replace')
        text_widget.insert(tk.END, result.stdout)
        if result.stderr:
            text_widget.insert(tk.END, f"Errors:\n{result.stderr}\n")
    except Exception as e:
        text_widget.insert(tk.END, f"Error en executar Enum4linux-ng: {e}\n")

#Funció per a llançar The Harvester per a admetre motor de cerca i límit
def llançar_the_harvester(domini, fonts, num_resultats, guardar_resultats, text_widget):
    text_widget.insert(tk.END, f"Llançant The Harvester per al domini '{domini}' amb motor '{fonts}' i límit de {num_resultats} resultats...\n")

    #Verifiquem si el script de The Harvester existeix
    script_path = "/home/alumnat/Escriptori/PROJECTE/theHarvester/theHarvester.py"
    if not os.path.exists(script_path):
        messagebox.showerror("Error", "L'script TheHarvester no es troba a la ruta especificada.")
        return
    comanda = f"python3 {script_path} -d {domini} -b {fonts} -l {num_resultats}"
    if guardar_resultats:
        fitxer_sortida = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Fitxers de text", "*.txt")])
        if fitxer_sortida:
            comanda += f" -f {fitxer_sortida}"
    try:
        subprocess.call(comanda, shell=True)
    except Exception as e:
        text_widget.insert(tk.END, f"Error en executar The Harvester: {e}\n")

#Funcions per a WHOIS, DNS i NSLOOKUP
def buscar_whois(domini, text_widget):
    print(f"Buscant WHOIS per: {domini}")
    try:
        resultat = subprocess.check_output(f"whois {domini}", shell=True, text=True, stderr=subprocess.STDOUT)
        text_widget.insert(tk.END, resultat)
        print("WHOIS fet.")
    except subprocess.CalledProcessError as e:
        text_widget.insert(tk.END, f"Error en executar whois: {e.output}\n")
        print(f"Error en whois: {e.output}")
    except Exception as e:
        text_widget.insert(tk.END, f"Error en executar whois: {e}\n")
        print(f"Error inesperat en whois: {e}")

def buscar_dns(domini, text_widget):
    text_widget.insert(tk.END, f"Obtenint informació DNS per al domini '{domini}'...\n")
    try:
        resultat = subprocess.check_output(f"dig {domini}", shell=True, text=True)
        text_widget.insert(tk.END, resultat)
    except Exception as e:
        text_widget.insert(tk.END, f"Error en executar dig: {e}\n")

def buscar_nslookup(domini, text_widget):
    text_widget.insert(tk.END, f"Obtenint informació de NS per al domini '{domini}'...\n")
    try:
        resultat = subprocess.check_output(f"nslookup {domini}", shell=True, text=True)
        text_widget.insert(tk.END, resultat)
    except Exception as e:
        text_widget.insert(tk.END, f"Error en executar nslookup: {e}\n")

#Funcions per a Nmap
def escaneig_nmap(target, opcio, text_widget):
    nm = nmap.PortScanner()
    if opcio == "1":
        text_widget.insert(tk.END, "Descobrint hosts de xarxa...\n")
        nm.scan(hosts=target, arguments='-sn')
        for host in nm.all_hosts():
            text_widget.insert(tk.END, f"Host descobert: {host}\n")
    elif opcio == "2":
        text_widget.insert(tk.END, "Escanejant ports oberts...\n")
        nm.scan(hosts=target, arguments='-p 1-1024')
        for host in nm.all_hosts():
            text_widget.insert(tk.END, f"Ports oberts a {host}: {nm[host].all_tcp()}\n")
    elif opcio == "3":
        text_widget.insert(tk.END, "Llistant serveis i versions...\n")
        nm.scan(hosts=target, arguments='-sV')
        for host in nm.all_hosts():
            text_widget.insert(tk.END, f"Serveis i versions a {host}:\n")
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    text_widget.insert(tk.END, f"Port {port}: {nm[host][proto][port]['name']} ({nm[host][proto][port]['version']})\n")
    elif opcio == "4":
        text_widget.insert(tk.END, "Llistant vulnerabilitats...\n")
        nm.scan(hosts=target, arguments='--script vuln')
        for host in nm.all_hosts():
            text_widget.insert(tk.END, f"Vulnerabilitats a {host}:\n")
            for script in nm[host].get('script', []):
                text_widget.insert(tk.END, f"- {script}: {nm[host]['script'][script]}\n")
    else:
        text_widget.insert(tk.END, "Opció no vàlida.\n")

#Funció per a enviar missatges a Telegram
def enviar_telegram(missatge):
    """Envía un missatge a Telegram utilitzant l'API de Telegram."""

    url_telegram = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    data = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": missatge
    }

    try:
        response = requests.post(url_telegram, data=data)
        response.raise_for_status()

        #Verifica la resposta del server
        json_response = response.json()
        if json_response.get("ok"):
            messagebox.showinfo("Telegram", "Missatge enviat correctament.")
        else:
            messagebox.showerror("Error", f"Error en enviar el missatge a Telegram: {json_response.get('description', 'Resposta desconeguda')}")
    except requests.exceptions.RequestException as e:  #Captura errors de xarxa
        messagebox.showerror("Error", f"Error a l'enviar el missatge a Telegram (error de conexió): {e}")
    except Exception as e:  #Errors
        messagebox.showerror("Error", f"Error a l'enviar el missatge a Telegram (error inesperat): {e}")

#Funció per a llançar ssh-audit
def auditoria_ssh(ip, text_widget):
    text_widget.insert(tk.END, f"Llançant ssh-audit per a la IP {ip}...\n")

    #Verifiquem si el script de ssh-audit existeix
    script_path = "/home/alumnat/Escriptori/PROJECTE/ssh-audit-master/ssh-audit.py"  #Ruta del script ssh-audit
    if not os.path.exists(script_path):
        messagebox.showerror("Error", "L'script ssh-audit no es troba a la ruta especificada.")
        return

    #Comanda per executar l'eina ssh-audit
    comanda = f"python3 {script_path} {ip}"

    #Preguntem si es vol guardar el resultat en un fitxer
    resposta = messagebox.askyesno("Guardar resultat", "Voleu desar els resultats en un fitxer?")
    if resposta:
        fitxer_sortida = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Fitxers de text", "*.txt")])
        if fitxer_sortida:
            comanda += f" > {fitxer_sortida}"  #Redirigir la sortida a un fitxer

    try:
        subprocess.call(comanda, shell=True)
        text_widget.insert(tk.END, f"Auditoria SSH completada per a la IP {ip}.\n")
    except Exception as e:
        text_widget.insert(tk.END, f"Error en executar ssh-audit: {e}\n")


#Interfície gràfica
def main():
    root = tk.Tk()
    root.title("Eina d'Auditoria")
    root.geometry("950x750") #Amplada de la finestra
    root.configure(bg="#e0f7fa")

    #Estil per als botons i altres elements
    estil_pestanyes = ttk.Style()
    estil_pestanyes.configure('TNotebook.Tab', background="#b2ebf2", foreground='black', padding=[10, 5], font=('Arial', 11))
    estil_boto = ttk.Style()
    estil_boto.configure('BotoArrodonit.TButton', font=('Arial', 12, 'bold'), foreground='#000080', background="#77C9E4", padding=10, relief='raised', borderwidth=0, borderradius=20)
    estil_menuboto = ttk.Style()
    estil_menuboto.configure('TMenubutton', font=('Arial', 12, 'bold'), foreground='#000080', background="#77C9E4", padding=10, relief='raised', borderradius=20)

    #Crear pestanyes
    notebook = ttk.Notebook(root, style='TNotebook')
    notebook.pack(pady=10, expand=True, fill="both")

    #Panell de desplaçament per als resultats
    text_widget = scrolledtext.ScrolledText(root, width=110, height=35, font=("Arial", 10), bg="#ffffff", fg="#000080", bd=1, relief="sunken", wrap=tk.WORD)
    text_widget.pack(padx=10, pady=10, expand=True, fill="both")

    #Pestanya de Shodan
    tab_shodan = ttk.Frame(notebook, padding=20)
    notebook.add(tab_shodan, text="Shodan")

    frame_entrada_shodan = tk.Frame(tab_shodan, bg="#e0f7fa")
    frame_entrada_shodan.pack(pady=10, fill=tk.X)

    tk.Label(frame_entrada_shodan, text="IP o Domini:", font=("Arial", 12), bg="#e0f7fa").pack(side=tk.LEFT, padx=5)
    entrada_ip_shodan = tk.Entry(frame_entrada_shodan, font=("Arial", 12), bg="#ffffff", fg="#000080", bd=2, relief="sunken")
    entrada_ip_shodan.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)

    frame_servei_shodan = tk.Frame(tab_shodan, bg="#e0f7fa")
    frame_servei_shodan.pack(pady=10, fill=tk.X)
    tk.Label(frame_servei_shodan, text="Nom del Servei (opcional):", font=("Arial", 12), bg="#e0f7fa").pack(side=tk.LEFT, padx=5)
    entrada_servei_shodan = tk.Entry(frame_servei_shodan, font=("Arial", 12), bg="#ffffff", fg="#000080", bd=2, relief="sunken")
    entrada_servei_shodan.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)

    boto_shodan = ttk.Button(tab_shodan, text="Cerca a Shodan", command=lambda: obtenir_informacio_ip_nou(entrada_ip_shodan.get(), entrada_servei_shodan.get(), text_widget), style='BotoArrodonit.TButton')
    boto_shodan.pack(pady=20)

    #Pestanya de The Harvester
    tab_harvester = ttk.Frame(notebook, padding=20)
    notebook.add(tab_harvester, text="The Harvester")

    frame_entrada_harvester = tk.Frame(tab_harvester, bg="#e0f7fa")
    frame_entrada_harvester.pack(pady=10, fill=tk.X)
    tk.Label(frame_entrada_harvester, text="Domini:", font=("Arial", 12), bg="#e0f7fa").pack(side=tk.LEFT, padx=5)
    entrada_domini_harvester = tk.Entry(frame_entrada_harvester, font=("Arial", 12), bg="#ffffff", fg="#000080", bd=2, relief="sunken")
    entrada_domini_harvester.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)

    frame_motor_harvester = tk.Frame(tab_harvester, bg="#e0f7fa")
    frame_motor_harvester.pack(pady=10, fill=tk.X) 
    tk.Label(frame_motor_harvester, text="Motor de Cerca:", font=("Arial", 12), bg="#e0f7fa").pack(side=tk.LEFT, padx=5)
    motors_busqueda = ["bing", "google", "baidu", "duckduckgo", "linkedin"] #Motors de cerca per exemple
    motor_busqueda_var = tk.StringVar(value=motors_busqueda[0])
    entrada_motor_harvester = ttk.Combobox(frame_motor_harvester, textvariable=motor_busqueda_var, values=motors_busqueda, state="readonly", font=("Arial", 12))
    entrada_motor_harvester.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)

    frame_limit_harvester = tk.Frame(tab_harvester, bg="#e0f7fa")
    frame_limit_harvester.pack(pady=10, fill=tk.X) 
    tk.Label(frame_limit_harvester, text="Límit de Resultats:", font=("Arial", 12), bg="#e0f7fa").pack(side=tk.LEFT, padx=5)
    entrada_limit_harvester = tk.Entry(frame_limit_harvester, font=("Arial", 12), bg="#ffffff", fg="#000080", bd=2, relief="sunken")
    entrada_limit_harvester.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
    entrada_limit_harvester.insert(0, "100") 

    boto_harvester = ttk.Button(tab_harvester, text="Llançar The Harvester", command=lambda: llançar_the_harvester(entrada_domini_harvester.get(), entrada_motor_harvester.get(), entrada_limit_harvester.get(), False, text_widget), style='BotoArrodonit.TButton')
    boto_harvester.pack(pady=20)

    #Pestanya de OSINT
    tab_osint = ttk.Frame(notebook, padding=20) 
    notebook.add(tab_osint, text="OSINT")

    frame_entrada_osint = tk.Frame(tab_osint, bg="#e0f7fa")
    frame_entrada_osint.pack(pady=10, fill=tk.X)
    tk.Label(frame_entrada_osint, text="Domini:", font=("Arial", 12), bg="#e0f7fa").pack(side=tk.LEFT, padx=5)
    entrada_domini_osint = tk.Entry(frame_entrada_osint, width=30, font=("Arial", 12), bg="#ffffff", fg="#000080", bd=2, relief="sunken")
    entrada_domini_osint.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)

    frame_menu_osint = tk.Frame(tab_osint, bg="#e0f7fa")
    frame_menu_osint.pack(pady=10)
    boto_whois = ttk.Button(frame_menu_osint, text="WHOIS", command=lambda: buscar_whois(entrada_domini_osint.get(), text_widget), style='BotoArrodonit.TButton')
    boto_whois.pack(side=tk.LEFT, padx=5)
    boto_dns = ttk.Button(frame_menu_osint, text="DNS", command=lambda: buscar_dns(entrada_domini_osint.get(), text_widget), style='BotoArrodonit.TButton')
    boto_dns.pack(side=tk.LEFT, padx=5)
    boto_nslookup = ttk.Button(frame_menu_osint, text="NSLOOKUP", command=lambda: buscar_nslookup(entrada_domini_osint.get(), text_widget), style='BotoArrodonit.TButton')
    boto_nslookup.pack(side=tk.LEFT, padx=5)

    #Pestanya de Nmap
    tab_nmap = ttk.Frame(notebook, padding=20)
    notebook.add(tab_nmap, text="Nmap")

    frame_entrada_nmap = tk.Frame(tab_nmap, bg="#e0f7fa") 
    frame_entrada_nmap.pack(pady=10, fill=tk.X) 
    tk.Label(frame_entrada_nmap, text="IP o Xarxa:", font=("Arial", 12), bg="#e0f7fa").pack(side=tk.LEFT, padx=5)
    entrada_ip_nmap = tk.Entry(frame_entrada_nmap, font=("Arial", 12), bg="#ffffff", fg="#000080", bd=2, relief="sunken")
    entrada_ip_nmap.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X) 

    frame_opcions_nmap = tk.Frame(tab_nmap, bg="#e0f7fa")
    frame_opcions_nmap.pack(pady=10, fill=tk.X)
    tk.Label(frame_opcions_nmap, text="Tipus d'escaneig:", font=("Arial", 12), bg="#e0f7fa").pack(side=tk.LEFT, padx=5)
    var_opcio_nmap = tk.StringVar(value="1")
    opcions_frame_nmap = tk.Frame(frame_opcions_nmap, bg="#e0f7fa")
    opcions_frame_nmap.pack(side=tk.LEFT, expand=True, fill=tk.X) 
    tk.Radiobutton(opcions_frame_nmap, text="Descobriment de Hosts", variable=var_opcio_nmap, value="1", font=("Arial", 12), bg="#e0f7fa").pack(side=tk.LEFT, padx=5)
    tk.Radiobutton(opcions_frame_nmap, text="Escaneig de Ports", variable=var_opcio_nmap, value="2", font=("Arial", 12), bg="#e0f7fa").pack(side=tk.LEFT, padx=5)
    tk.Radiobutton(opcions_frame_nmap, text="Serveis i Versions", variable=var_opcio_nmap, value="3", font=("Arial", 12), bg="#e0f7fa").pack(side=tk.LEFT, padx=5)
    tk.Radiobutton(opcions_frame_nmap, text="Vulnerabilitats", variable=var_opcio_nmap, value="4", font=("Arial", 12), bg="#e0f7fa").pack(side=tk.LEFT, padx=5)

    boto_nmap = ttk.Button(tab_nmap, text="Llançar Nmap", command=lambda: escaneig_nmap(entrada_ip_nmap.get(), var_opcio_nmap.get(), text_widget), style='BotoArrodonit.TButton')
    boto_nmap.pack(pady=20)

    #Pestanya d'Auditoria SSH
    tab_ssh_audit = ttk.Frame(notebook, padding=20) 
    notebook.add(tab_ssh_audit, text="Auditoria SSH")

    frame_entrada_ssh_audit = tk.Frame(tab_ssh_audit, bg="#e0f7fa")
    frame_entrada_ssh_audit.pack(pady=10, fill=tk.X)
    tk.Label(frame_entrada_ssh_audit, text="IP:", font=("Arial", 12), bg="#e0f7fa").pack(side=tk.LEFT, padx=5)
    entrada_ip_ssh_audit = tk.Entry(tab_ssh_audit, font=("Arial", 12), bg="#ffffff", fg="#000080", bd=2, relief="sunken")
    entrada_ip_ssh_audit.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
    boto_ssh_audit = ttk.Button(tab_ssh_audit, text="Auditoria SSH", command=lambda: auditoria_ssh(entrada_ip_ssh_audit.get(), text_widget), style='BotoArrodonit.TButton')
    boto_ssh_audit.pack(pady=20) 

    #Pestanya d'Enumeració
    tab_enumeracio = ttk.Frame(notebook, padding=20)
    notebook.add(tab_enumeracio, text="Enumeració")

    frame_entrada_enumeracio = tk.Frame(tab_enumeracio, bg="#e0f7fa") 
    frame_entrada_enumeracio.pack(pady=10, fill=tk.X) 
    tk.Label(frame_entrada_enumeracio, text="IP:", font=("Arial", 12), bg="#e0f7fa").pack(side=tk.LEFT, padx=5)
    entrada_ip_enumeracio = tk.Entry(tab_enumeracio, font=("Arial", 12), bg="#ffffff", fg="#000080", bd=2, relief="sunken") 
    entrada_ip_enumeracio.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X) 
    boto_enum = ttk.Button(tab_enumeracio, text="Enumeració Enum4Linux", command=lambda: llançar_enum4linux(entrada_ip_enumeracio.get(), text_widget), style='BotoArrodonit.TButton')
    boto_enum.pack(pady=20) 

    #Pestanya de Telegram
    tab_telegram = ttk.Frame(notebook, padding=20) 
    notebook.add(tab_telegram, text="Telegram")
    boto_telegram = ttk.Button(tab_telegram, text="Enviar a Telegram", command=lambda: enviar_telegram(text_widget.get("1.0", tk.END)), style='BotoArrodonit.TButton')
    boto_telegram.pack(pady=30, padx=30)

    root.mainloop()

if __name__ == "__main__":
    main()