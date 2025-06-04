import logging
import sys
import yaml
import customtkinter
import asyncio
import main
import threading

# from PIL import Image, ImageTk
# import PIL

# to be done:
# run button
# change location functionality
# log window

customtkinter.set_appearance_mode("dark")


class TextboxFrame(customtkinter.CTkFrame):
    def __init__(self, master, title, route_file="route.txt"):
        super().__init__(master)
        self.route_file = route_file
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self.title = title
        self.title = customtkinter.CTkLabel(
            self, text=self.title, fg_color="gray30", corner_radius=6
        )
        self.title.grid(row=0, column=0, padx=10, pady=(10, 0), sticky="ew")

        self.textbox = customtkinter.CTkTextbox(self)
        self.textbox.grid(row=1, column=0, padx=10, pady=(10, 10), sticky="nsew")

        self.load_route_file()

    def load_route_file(self):
        try:
            with open(self.route_file, "r") as f:
                content = f.read()
                self.textbox.insert("0.0", content)
            print(f"Loaded {self.route_file} successfully.")
        except FileNotFoundError:
            print(f"Warning: {self.route_file} not found.")
            self.textbox.insert("0.0", f"# {self.route_file} not found.")

    def get(self):
        return self.textbox.get("0.0", "end")


class LogFrame(customtkinter.CTkFrame):
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
        self.textbox.configure(state="disabled")

        sys.stdout = self
        sys.stderr = self

    def write(self, message):
        self.textbox.configure(state="normal")
        self.textbox.insert("end", message)
        self.textbox.see("end")
        self.textbox.configure(state="disabled")

    def flush(self):
        pass

    def redirect_logging(self):
        class TextHandler(logging.Handler):
            def __init__(self, text_widget):
                super().__init__()
                self.text_widget = text_widget

            def emit(self, record):
                msg = self.format(record) + "\n"
                self.text_widget.configure(state="normal")
                self.text_widget.insert("end", msg)
                self.text_widget.see("end")
                self.text_widget.configure(state="disabled")

        handler = TextHandler(self.textbox)
        handler.setFormatter(
            logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        )

        logging.getLogger().addHandler(handler)


class ConfigFrame(customtkinter.CTkFrame):
    def __init__(self, master, title="Configuration", config_file="config.yaml"):
        super().__init__(master)
        self.config_file = config_file

        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=2, minsize=110)

        self.title = title
        self.title = customtkinter.CTkLabel(
            self, text=self.title, fg_color="gray30", corner_radius=6
        )
        self.title.grid(
            row=0, column=0, columnspan=2, padx=10, pady=(10, 0), sticky="ew"
        )

        self.v_label = customtkinter.CTkLabel(self, text="Velocity: 3.0 m/s", width=110)
        self.v_label.grid(row=1, column=0, padx=(10, 10), pady=(10, 0), sticky="ew")
        self.v_slider = customtkinter.CTkSlider(
            self, from_=0, to=6, number_of_steps=60, command=self.update_slider_value_v
        )
        self.v_slider.grid(row=1, column=1, padx=10, pady=(10, 0), sticky="ew")

        self.n_lap_label = customtkinter.CTkLabel(
            self, text="Number of laps: 8", width=120
        )
        self.n_lap_label.grid(row=2, column=0, padx=(10, 10), pady=(10, 0), sticky="ew")
        self.n_lap_slider = customtkinter.CTkSlider(
            self, from_=1, to=10, number_of_steps=9, command=self.update_slider_value_n
        )
        self.n_lap_slider.grid(row=2, column=1, padx=10, pady=(10, 0), sticky="ew")

        self.load_config()

    def load_config(self):
        try:
            with open(self.config_file, "r") as f:
                config_data = yaml.safe_load(f)
                print(f"Loaded {self.config_file}: {config_data}")

                v_value = config_data.get("v", 3.0)
                n_laps_value = config_data.get("n_laps", 8)

                self.v_slider.set(v_value)
                self.update_slider_value_v(v_value)

                self.n_lap_slider.set(n_laps_value)
                self.update_slider_value_n(n_laps_value)

        except FileNotFoundError:
            print(f"Warning: {self.config_file} not found. Using defaults.")
            self.v_slider.set(3.0)
            self.update_slider_value_v(3.0)

            self.n_lap_slider.set(8)
            self.update_slider_value_n(8)

    def update_slider_value_v(self, value):
        self.v_label.configure(text=f"Velocity: {value:.1f} m/s")

    def update_slider_value_n(self, value):
        self.n_lap_label.configure(text=f"Number of laps: {int(value)}")

    def get_v(self):
        return self.v_slider.get()

    def get_n_lap(self):
        return self.n_lap_slider.get()

        # image_pil = Image.open("assets/xianbei.png")
        # image_pil = image_pil.resize((200, 200))
        # self.velocity_image = ImageTk.PhotoImage(image_pil)

        # self.image_label = customtkinter.CTkLabel(
        #     self, image=self.velocity_image, text=""
        # )
        # self.image_label.grid(
        #     row=3, column=0, columnspan=2, pady=(0, 10)
        # )


class ActionsFrame(customtkinter.CTkFrame):
    def __init__(self, master, title, config_frame, textbox_frame):
        super().__init__(master)
        self.grid_columnconfigure(0, weight=1)

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
            self,
            text="Change Location (not implemented yet)",
            command=self.change_location_callback,
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
        self.stop_button = customtkinter.CTkButton(
            self, text="Stop", command=self.stop_callback
        )
        self.stop_button.grid(
            row=4, column=0, padx=10, pady=(10, 0), sticky="nsew", columnspan=2
        )
        self.quit_button = customtkinter.CTkButton(
            self, text="Quit", command=self.quit_callback
        )
        self.quit_button.grid(
            row=5, column=0, padx=10, pady=(10, 0), sticky="ew", columnspan=2
        )


    def run_callback(self):
        print("Run button clicked. Starting main()...")

        def run_async_main():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(main.main())

        threading.Thread(target=run_async_main, daemon=True).start()

        print("main() coroutine started.")

    def stop_callback(self):
        print("Stop button clicked. Stopping main thread...")

        main.stop_event.set()

        if self.run_thread is not None:
            self.run_thread.join(timeout=5)
            print("Main thread stopped.")


    def quit_callback(self):
        self.master.destroy()

    def change_location_callback(self):
        pass

    def save_callback(self):
        v_value = self.config_frame.get_v()
        n_laps_value = int(self.config_frame.get_n_lap())
        route_path = "route.txt"

        config_data = {
            "v": round(v_value, 1),
            "n_laps": int(n_laps_value),
            "routeConfig": route_path,
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
        self.grid_rowconfigure(0, weight=1, minsize=130)

        self.textbox_frame = TextboxFrame(self, "Coordinates")
        self.textbox_frame.grid(
            row=0, column=0, padx=(10, 5), pady=(10, 10), sticky="nsew", rowspan=3
        )

        self.config_frame = ConfigFrame(self, "Configuration")
        self.config_frame.grid(
            row=0, column=1, padx=(5, 10), pady=(10, 5), sticky="nsew"
        )

        self.actions_frame = ActionsFrame(
            self,
            "Actions",
            config_frame=self.config_frame,
            textbox_frame=self.textbox_frame,
        )
        self.actions_frame.grid(
            row=1, column=1, padx=(5, 10), pady=(5, 5), sticky="nsew"
        )

        self.log_frame = LogFrame(self, "Log")
        self.log_frame.grid(row=2, column=1, padx=(5, 10), pady=(5, 10), sticky="nsew")
        self.log_frame.redirect_logging()

if __name__ == "__main__":
    app = App()
    app.mainloop()
