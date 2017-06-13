
def open_telnet_conn(ip):

    try:

        connection = telnetlib.Telnet(ip, 23, 5)

        output = connection.read_until("name:", READ_TIMEOUT)
        connection.write(username + "\n")

        output = connection.read_until("word:", READ_TIMEOUT)
        connection.write(password + "\n")
        time.sleep(1)


        connection.write("\n")
        connection.write("configure terminal\n")
        time.sleep(1)

        selected_cmd_file = open(cmd_file, 'r')

        selected_cmd_file.seek(0)

        for each_line in selected_cmd_file.readlines():
            connection.write(each_line + '\n')
            time.sleep(1)


        selected_cmd_file.close()

        connection.close()

    except IOError:
        print "Input parameter error! Please check username, password and file name."

open_telnet_conn(ip)

