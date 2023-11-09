from io import BytesIO
from os.path import splitext
from abc import abstractclassmethod, ABC

import fitz
from docx2txt import process
from django.core.files.uploadedfile import InMemoryUploadedFile


class Reader(ABC):

    @abstractclassmethod
    def read(self, file: InMemoryUploadedFile) -> str:
        pass


class PDFReader(Reader):

    def read(self, file: InMemoryUploadedFile) -> str:
        text = ""
        in_memory_pdf = BytesIO(file.read())  # Создаем байтовый поток из содержимого InMemoryUploadedFile
        document = fitz.open(stream=in_memory_pdf, filetype="pdf")  # Открываем PDF из байтового потока
        for page_num in range(document.page_count):
            page = document.load_page(page_num)
            text += page.get_text("text")
        return text


class TXTReader(Reader):

    def read(self, file: InMemoryUploadedFile) -> str:
        text = file.file.read()
        return text.decode("utf-8")


class DOCXReader(Reader):

    def read(self, file: InMemoryUploadedFile) -> str:
        text = process(file.file)
        return text
    

READERS = {'.pdf': PDFReader(), '.txt': TXTReader, '.docx': DOCXReader()}


def read_file(file: InMemoryUploadedFile) -> str:
    filename = file.name
    _, file_extension = splitext(filename)

    try:
        reader = READERS[file_extension]
    except KeyError as e:
        return None
    
    return reader.read(file)
    

def normalize_filename(filename):
    filename = filename.replace(" ", "_")
    filename = filename.lower()
    return filename