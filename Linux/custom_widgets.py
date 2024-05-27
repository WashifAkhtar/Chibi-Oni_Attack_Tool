import customtkinter as ctk

class CustomLabel(ctk.CTkLabel):
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)

class CustomEntry(ctk.CTkEntry):
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)

class CustomButton(ctk.CTkButton):
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)

class CustomTextBox(ctk.CTkTextbox):
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)

class CustomScrollbar(ctk.CTkScrollbar):
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)
