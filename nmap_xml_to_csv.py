import xml.etree.ElementTree as ET
import csv
import argparse

def parse_nmap_xml_to_csv(xml_file, csv_file):
    try:
        context = ET.iterparse(xml_file, events=('end',))
    except ET.ParseError as e:
        print(f"Ошибка парсинга XML: {e}")
        return

    with open(csv_file, mode='w', newline='') as file:
        csv_writer = csv.writer(file)

        headers = ['IP Address', 'Port', 'Protocol', 'State', 'Service Name', 'Service Version']
        csv_writer.writerow(headers)

        try:
            for event, elem in context:
                if elem.tag == 'host':
                    address = elem.find('address').get('addr')

                    for port in elem.findall('ports/port'):
                        port_id = port.get('portid')
                        protocol = port.get('protocol')
                        state = port.find('state').get('state')

                        service = port.find('service')
                        service_name = service.get('name') if service is not None else 'N/A'
                        service_version = service.get('version') if service is not None else 'N/A'

                        csv_writer.writerow([address, port_id, protocol, state, service_name, service_version])

                    elem.clear()
        except ET.ParseError:
            print("Обнаружен незакрытый XML файл. Обрабатываю доступные данные.")

    print(f'Парсинг завершен. Результат сохранен в {csv_file}')

def main():
    parser = argparse.ArgumentParser(description='Парсинг Nmap XML в CSV формат.')
    parser.add_argument('xml_file', help='Путь к XML файлу, сгенерированному Nmap.')
    parser.add_argument('csv_file', help='Путь к выходному CSV файлу.')

    args = parser.parse_args()

    parse_nmap_xml_to_csv(args.xml_file, args.csv_file)

if __name__ == '__main__':
    main()
