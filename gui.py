import yaml
import customtkinter
# from PIL import Image, ImageTk
# import PIL

# to be done:
# run button
# change location functionality
# log window

customtkinter.set_appearance_mode("dark")


class TextboxFrame(customtkinter.CTkFrame):
    def __init__(self, master, title):
        super().__init__(master)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        self.title = title
        self.title = customtkinter.CTkLabel(
            self, text=self.title, fg_color="gray30", corner_radius=6
        )
        self.title.grid(row=0, column=0, padx=10, pady=(10, 0), sticky="ew")

        self.textbox = customtkinter.CTkTextbox(self)
        self.textbox.grid(row=1, column=0, padx=10, pady=(10, 10), sticky="nsew")

    def get(self):
        return self.textbox.get("0.0", "end")


class LogFrame(customtkinter.CTkFrame):
    def __init__(self, master, title):
        super().__init__(master)
        self.grid_columnconfigure(0, weight=1)
        # self.grid_rowconfigure(1, weight=1)
        self.title = title
        self.title = customtkinter.CTkLabel(
            self, text=self.title, fg_color="gray30", corner_radius=6
        )
        self.title.grid(row=0, column=0, padx=10, pady=(10, 0), sticky="ew")

        self.textbox = customtkinter.CTkTextbox(self)
        self.textbox.grid(row=1, column=0, padx=10, pady=(10, 10), sticky="nsew")
        self.textbox.configure(state="disabled")


class ConfigFrame(customtkinter.CTkFrame):
    def __init__(self, master, title="Configuration"):
        super().__init__(master)
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=2, minsize=110)
        self.title = title
        self.title = customtkinter.CTkLabel(
            self, text=self.title, fg_color="gray30", corner_radius=6
        )
        self.title.grid(
            row=0, column=0, columnspan=2, padx=10, pady=(10, 0), sticky="ew"
        )

        self.v_label = customtkinter.CTkLabel(self, text="0", width=110)
        self.v_label.grid(row=1, column=0, padx=(10, 10), pady=(10, 0), sticky="ew")
        self.v_label.configure(text="Velocity: 3.0 m/s")
        self.v_slider = customtkinter.CTkSlider(
            self, from_=0, to=6, number_of_steps=60, command=self.update_slider_value_v
        )
        self.v_slider.grid(row=1, column=1, padx=10, pady=(10, 0), sticky="ew")
        self.v_slider.set(3.0)

        self.n_lap_label = customtkinter.CTkLabel(
            self, text="Number of laps: 8", width=120
        )
        self.n_lap_label.grid(row=2, column=0, padx=(10, 10), pady=(10, 0), sticky="ew")
        self.n_lap_label.configure(text="Number of laps: 8")
        self.n_lap_slider = customtkinter.CTkSlider(
            self, from_=1, to=10, number_of_steps=9, command=self.update_slider_value_n
        )
        self.n_lap_slider.grid(row=2, column=1, padx=10, pady=(10, 0), sticky="ew")
        self.n_lap_slider.set(8)

        # image_pil = Image.open("assets/xianbei.png")
        # image_pil = image_pil.resize((200, 200))
        # self.velocity_image = ImageTk.PhotoImage(image_pil)

        # self.image_label = customtkinter.CTkLabel(
        #     self, image=self.velocity_image, text=""
        # )
        # self.image_label.grid(
        #     row=3, column=0, columnspan=2, pady=(0, 10)
        # )

    def update_slider_value_v(self, value):
        self.v_label.configure(text=f"Velocity: {value:.1f} m/s")

    def update_slider_value_n(self, value):
        self.n_lap_label.configure(text=f"Number of laps: {int(value)}")

    def get_v(self):
        return self.v_slider.get()

    def get_n_lap(self):
        return self.n_lap_slider.get()


class ActionsFrame(customtkinter.CTkFrame):
    def __init__(self, master, title, config_frame, textbox_frame):
        super().__init__(master)
        self.grid_columnconfigure(0, weight=1)
        # self.grid_rowconfigure([0, 1, 2, 3], weight=1)
        # self.grid_columnconfigure(1, weight=2, minsize=110)
        self.config_frame = config_frame
        self.textbox_frame = textbox_frame

        self.title = title
        self.title = customtkinter.CTkLabel(
            self, text=self.title, fg_color="gray30", corner_radius=6
        )
        self.title.grid(
            row=0, column=0, columnspan=2, padx=10, pady=(10, 0), sticky="ew"
        )

        self.save_button = customtkinter.CTkButton(
            self, text="Save Configuration", command=self.save_callback
        )
        self.save_button.grid(
            row=1, column=0, padx=10, pady=(10, 0), sticky="ew", columnspan=2
        )

        self.change_location_button = customtkinter.CTkButton(
            self, text="Change Location", command=self.change_location_callback
        )
        self.change_location_button.grid(
            row=2, column=0, padx=10, pady=(10, 0), sticky="ew", columnspan=2
        )

        self.run_button = customtkinter.CTkButton(
            self, text="Run", command=self.run_callback
        )
        self.run_button.grid(
            row=3, column=0, padx=10, pady=(10, 0), sticky="nsew", columnspan=2
        )

        self.quit_button = customtkinter.CTkButton(
            self, text="Quit", command=self.quit_callback
        )
        self.quit_button.grid(
            row=4, column=0, padx=10, pady=(10, 0), sticky="ew", columnspan=2
        )

    def run_callback(self):
        pass

    def quit_callback(self):
        self.master.destroy()

    def change_location_callback(self):
        pass

    def save_callback(self):
        pass
    def save_callback(self):
        v_value = self.config_frame.get_v()
        n_laps_value = int(self.config_frame.get_n_lap())
        route_path = "route.txt"

        config_data = {
            'v': round(v_value, 1),
            'n_laps': int(n_laps_value),
            'routeConfig': route_path
        }

        coords = self.textbox_frame.get().strip()
        with open("config.yaml", "w") as f:
            yaml.dump(config_data, f)

        with open(route_path, "w") as f:
            if coords:
                f.write(coords)
            else:
                f.write("")

        print("Configuration saved:", config_data)

class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        self.title("iOSRealRun-18")
        self.geometry("800x600")
        self.grid_columnconfigure(0, weight=1, minsize=400)
        self.grid_columnconfigure(1, weight=1, minsize=400)
        self.grid_rowconfigure(0, weight=1, minsize=140)
        # self.grid_rowconfigure(1, weight=4)

        # self.textbox_frame = TextboxFrame(self, "Coordinates")
        # self.textbox_frame.grid(
        #     row=0, column=0, padx=(10, 5), pady=(10, 0), sticky="nsew", rowspan=3
        # )

        # self.log_frame = LogFrame(self, "Log")
        # self.log_frame.grid(row=1, column=0, padx=(10, 5), pady=(10, 10), sticky="nsew")

        # self.config_frame = ConfigFrame(self, "Configuration")
        # self.config_frame.grid(
        #     row=0, column=1, padx=(5, 10), pady=(10, 0), sticky="nsew"
        # )

        # self.actions_frame = ActionsFrame(self, "Actions")
        # self.actions_frame.grid(
        #     row=1, column=1, padx=(5, 10), pady=(10, 10), sticky="nsew"
        # )

        self.textbox_frame = TextboxFrame(self, "Coordinates")
        self.textbox_frame.grid(
            row=0, column=0, padx=(10, 5), pady=(10, 10), sticky="nsew", rowspan=3
        )



        self.config_frame = ConfigFrame(self, "Configuration")
        self.config_frame.grid(
            row=0, column=1, padx=(5, 10), pady=(10, 5), sticky="nsew"
        )

        self.actions_frame = ActionsFrame(self, "Actions", config_frame=self.config_frame, textbox_frame=self.textbox_frame)
        self.actions_frame.grid(
            row=1, column=1, padx=(5, 10), pady=(5, 5), sticky="nsew"
        )

        self.log_frame = LogFrame(self, "Log")
        self.log_frame.grid(row=2, column=1, padx=(5, 10), pady=(5, 10), sticky="nsew")

    #     self.button = customtkinter.CTkButton(
    #         self, text="my button", command=self.button_callback
    #     )
    #     self.button.grid(row=3, column=0, padx=10, pady=10, sticky="ew", columnspan=2)

    # def button_callback(self):
    #     print(self.textbox_frame.get())
    #     print(f"Velocity: {self.config_frame.get_v()} m/s")
    #     print(f"Number of laps: {self.config_frame.get_n_lap()}")


app = App()
app.mainloop()
