from reportlab.platypus import SimpleDocTemplate
from reportlab.platypus.tables import Table
cm = 2.54

def print_pdf(modeladmin, request, queryset):
    response = HttpResponse(mimetype='application/pdf')
    response['Content-Disposition'] = 'attachment; filename=somefilename.pdf'

    elements = []

    doc = SimpleDocTemplate(response, rightMargin=0, leftMargin=6.5 * cm, topMargin=0.3 * cm, bottomMargin=0)

    data=[(1,2),(3,4)]
    table = Table(data, colWidths=270, rowHeights=79)
    elements.append(table)
    doc.build(elements) 
    return response
