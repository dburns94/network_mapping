#!/usr/bin/python3.6
import sys
#import re

from parse import remove_end_spaces

theme = None

def alert(message):
    print(f"<script>alert(\"{message}\");</script>")

def print_error_msg(msg):
    print("<div class=\"error_msg\">%s</div>" % msg)

###############
##### NEW #####
###############
def open(style=None):
    # open HTML
    print("Content-type:text/html\r\n\r\n")
    print("<html><body>")
    if style is None:
        print_styling()
    elif style.lower() == 'code':
        print_code_styling()

def print_styling():
    # print HTML styling
    style = """
<style>
body {
    background-color: #15609C;
    text-shadow: 1px 1px #000000;
    color: white;
    font-size: 18px;
    white-space: nowrap;
}
table.data {
    border: 1px solid black;
    border-collapse: collapse;
    font-size: 16px;
    white-space: nowrap;
}
table.data tr {
    border:1px solid white;
}
table.data th {
    border: 1px solid white;
    padding: 8px;
    border-bottom: double;
    background-color: rgba(0, 0, 0, 0.3);
}
table.data th.table_header {
    border-bottom: double;
}
table.data.vertical th {
    border-bottom: 1px solid;
    border-right: double;
}
table.data.vertical th.table_header {
    border-bottom: double;
}
table.data td {
    border: 1px solid white;
    padding: 6px 8px 6px 8px;
    text-align: center;
    background-color: rgba(0, 0, 0, 0.1);
}
.code-block {
    display: inline-block;
    padding: 4px;
    border: 1px solid black;
    border-radius: 4px;
    background-color: rgba(143, 139, 141, 0.8);
    margin-right: 10px;
    margin-bottom: 2px;
}
.code {
    border-radius: 2px;
    margin-right: 4px;
    padding: 0px 4px 0px 4px;
}
.code:hover {
    background-color: rgba(0, 0, 0, 0.2);
}
.smokey {
    font-size:110%;
    text-shadow: -1px  0px 5px #202020,
                  0px  1px 5px #202020,
                  1px  0px 5px #202020,
                  0px -1px 5px #202020;
}
.error_msg {
    color: red;
    font-weight: bold;
    font-size: 22px;
}
ol {
    margin: 0px;
}
pre {
    margin: 0px;
}
</style>
"""
    print(style)

def print_code_styling():
    # print HTML styling
    style = """
<style>
body {
    background-color: #000020;
    color: white;
}
</style>
"""
    print(style)

def add_javascript():
    # background-color: rgba(143, 139, 141, 0.8)
    javascript = """
<style>
.content_toggle {
    color: white;
    text-shadow: 1px 1px #000000;
    border: 1px solid black;
    border-radius: 5px;
"""
    if theme == 'Dark':
        javascript += "    background-color: #4d5359 !important;"
    else:
        javascript += "    background-color: #817d7f !important;"
    javascript += """
    display: inline-block;
    padding: 6px 8px;
    cursor: zoom-in;
    margin-bottom: 1px;
    font-weight: bold;
}
</style>
<script>
function content_toggle(event) {
  let element = event.target;
  let content = element.nextElementSibling.nextElementSibling;
  let content_br = content.nextElementSibling;
  if (content) {
    if (content.style.display === "block") {
      content.style.display = "none";
      if (!element.classList.contains("displayFilters")) {
        element.style.cursor = "zoom-in";
      }
      content_br.style.display = "none";
    } else {
      content.style.display = "block";
      if (!element.classList.contains("displayFilters")) {
        element.style.cursor = "zoom-out";
      }
      content_br.style.display = "";
    }
  }
}
</script>
"""
    print(javascript)

def make_table(rows, table_class='data', header=None, vertical=False):
    # start HTML table using the formatting above
    # create table class
    html_class = ''
    if table_class is not None:
        html_class = f" class=\"{table_class}"
        if vertical:
            html_class += ' vertical'
    table_string = f"<table{html_class}\">"
    if header is not None:
        table_string += f"<tr><th class=\"table_header\"colspan=\"100\">{header}</th></tr>"
    if not vertical:
        # add the header row
        table_string += "<tr>"
        for col in rows[0]:
            table_string += f"<th valign='bottom'>{col}</th>"
        table_string += "</tr>"
        # add all the data rows
        for row in rows[1:]:
            table_string += "<tr>"
            for col in row:
                table_string += f"<td>{col}</td>"
            table_string += "</tr>"
    else:
        for row in rows:
            table_string += "<tr>"
            for i in range(len(row)):
                if i == 0:
                    table_string += f"<th valign='bottom'>{row[i]}</th>"
                else:
                    table_string += f"<td>{row[i]}</td>"
            table_string += "</tr>"
    # close the HTML table
    table_string += "</table>"
    return table_string

def make_output(text):
    # replace characters that need displayed differently
    replacements = [
                                    ['\n', '<br>'],
                                    [' ', '&nbsp;']
                                  ]
    for replacement in replacements:
        text = text.replace(replacement[0], replacement[1])
    return text+'<br>'

def make_code(text, hidden=False):
    style = ''
    # remove end spaces from the code
    text = '\n'.join(remove_end_spaces(text.split('\n')))
    #text = re.sub(r"[ ]{50,}", "\n", text)
    # replace characters that need displayed differently
    replacements = [
                                    ['\n', '<br>'],
                                    [' ', '&nbsp;']
                                  ]
    for replacement in replacements:
        text = text.replace(replacement[0], replacement[1])
    # if user wants code hidden
    if hidden:
        style += 'display:none;'
        br_style += 'display:none;'
    # wrap the font
    return f"<pre class=\"code-block\" style=\"{style}\">{text}</pre><br style=\"{style}\">"

def make_code_max(text, height='20', hidden=False):
    style = ''
    br_style = ''
    # remove end spaces from the code
    text = '\n'.join(remove_end_spaces(text.split('\n')))
    #text = re.sub(r"[ ]{50,}", "\n", text)
    # determine if lines are over max
    maxed_out = True if len(text.split('\n')) > int(height) else False
    # replace characters that need displayed differently
    replacements = [
                                    ['\n', '<br>'],
                                    [' ', '&nbsp;']
                                  ]
    for replacement in replacements:
        text = text.replace(replacement[0], replacement[1])
    # if user wants code hidden
    if hidden:
        style += 'display:none;'
        br_style += 'display:none;'
    # wrap the font
    if maxed_out:
        return f"<pre class=\"code-block\" style=\"overflow-x:hidden;min-width:min-content;max-height:{height}em;overflow-y:scroll;{style}\">{text}</pre><br style=\"{br_style}\">"
    return f"<pre class=\"code-block\" style=\"{style}\">{text}</pre><br style=\"{br_style}\">"

def content_toggle(text):
    return f"<div class='content_toggle' onclick='content_toggle(event);'>{text}</div><br>"

def close():
    # close HTML
    print("</body></html>")


def open_iframe(form):
    print("Content-type:text/html\r\n\r\n")
    open_string = """
<html><body>
"""
    global theme
    theme = style_iframe(form)
    print(open_string)
    return theme

def style_iframe(form):
    theme = form.getfirst('theme', None)
    style_string = "<link rel='stylesheet' href='https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/css/bootstrap.min.css' integrity='sha384-Vkoo8x4CGsO3+Hhxv8T/Q5PaXtkKtu6ug5TOeNV6gBiFeWPGFN9MuhOf23Q9Ifjh' crossorigin='anonymous'>"
    style_string += """
<style>
body {
    background-color: rgba(0, 0, 0, 0);
    font-size: 20px;
    white-space: nowrap;
"""
    if theme == 'Dark':
        style_string += """
    color: white;
    text-shadow: 1px 1px #000000;
"""
    style_string += """
}
.bg-dark2 {
    background-color: #4d5359 !important;
}
.code-block {
    color: white;
    text-shadow: 1px 1px #000000;
    display: inline-block;
    padding: 4px;
    border: 1px solid black;
    border-radius: 4px;
"""
    if theme == 'Dark':
        style_string += "background-color: #4d5359 !important;"
    else:
        style_string += "background-color: #817d7f !important;"
    style_string += """
    margin-right: 10px;
    margin-bottom: 2px;
}
.table {
    white-space: nowrap;
    width: auto;
}
.smokey {
    color: white;
    font-size:110%;
    text-shadow: -1px  0px 5px #202020,
                  0px  1px 5px #202020,
                  1px  0px 5px #202020,
                  0px -1px 5px #202020;
}
.error_msg {
    color: red;
    font-weight: bold;
    font-size: 22px;
}
</style>
"""
    print(style_string)
    return theme

def make_table(rows, table_class='data', header=None, vertical=False):
    # start HTML table using the formatting above
    # create table class
    table_class = "table table-bordered"
    if theme == 'Dark':
        table_class += " table-dark"
    # start HTML table
    table_string = f"<table class='{table_class}'>"
    # if a header was provided
    if header is not None:
        # create the header class
        header_class = "text-center"
        if theme == 'Dark':
            header_class += " thead-dark"
        else:
            header_class += " bg-dark2 text-white"
        # add the header
        table_string += f"<thead class=\"{header_class}\"><tr><th colspan=\"100\">{header}</th></tr></thead>"
    if theme == 'Dark':
        row_class = "thead-dark"
        th_class = "text-center"
    else:
        row_class = ""
        th_class = "text-center bg-dark2 text-white"
    # if this is a vertical table
    if not vertical:
        # add the header row
        table_string += f"<tr class={row_class}>"
        for col in rows[0]:
            table_string += f"<th class='{th_class}' valign='bottom'>{col}</th>"
        table_string += "</tr>"
        # add all the data rows
        for row in rows[1:]:
            table_string += "<tr>"
            for col in row:
                table_string += f"<td>{col}</td>"
            table_string += "</tr>"
    else:
        for row in rows:
            table_string += f"<tr class={row_class}>"
            for i in range(len(row)):
                if i == 0:
                    table_string += f"<th class='{th_class}' valign='bottom'>{row[i]}</th>"
                else:
                    table_string += f"<td>{row[i]}</td>"
            table_string += "</tr>"
    # close the HTML table
    table_string += "</table>"
    return table_string

def close_iframe():
    print("</body></html>")

