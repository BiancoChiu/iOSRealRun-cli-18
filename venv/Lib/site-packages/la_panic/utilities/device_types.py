from la_panic.utilities.design_pattern.singleton import Singleton


class iPhoneModel(object):
    def __init__(self, product_type: str, hardware_model: str, board_id: hex, chip_id: hex, display_name: str):
        self.__product_type = product_type
        self.__hardware_model = hardware_model
        self.__board_id = board_id
        self.__chip_id = chip_id
        self.__display_name = display_name

    @property
    def product_type(self) -> str:
        return self.__product_type

    @property
    def name(self) -> str:
        return self.__display_name


class iPhoneModels(object, metaclass=Singleton):
    __models: [iPhoneModel]

    def __init__(self):
        self.__models = [
            iPhoneModel(product_type='iPhone1,1', hardware_model='m68ap', board_id=0x00, chip_id=0x8900,
                        display_name='iPhone 2G'),
            iPhoneModel(product_type='iPhone1,2', hardware_model='n82ap', board_id=0x04, chip_id=0x8900,
                        display_name='iPhone 3G'),
            iPhoneModel(product_type='iPhone2,1', hardware_model='n88ap', board_id=0x00, chip_id=0x8920,
                        display_name='iPhone 3Gs'),
            iPhoneModel(product_type='iPhone3,1', hardware_model='n90ap', board_id=0x00, chip_id=0x8930,
                        display_name='iPhone 4 (GSM)'),
            iPhoneModel(product_type='iPhone3,2', hardware_model='n90bap', board_id=0x04, chip_id=0x8930,
                        display_name='iPhone 4 (GSM) R2 2012'),
            iPhoneModel(product_type='iPhone3,3', hardware_model='n92ap', board_id=0x06, chip_id=0x8930,
                        display_name='iPhone 4 (CDMA)'),
            iPhoneModel(product_type='iPhone4,1', hardware_model='n94ap', board_id=0x08, chip_id=0x8940,
                        display_name='iPhone 4s'),
            iPhoneModel(product_type='iPhone5,1', hardware_model='n41ap', board_id=0x00, chip_id=0x8950,
                        display_name='iPhone 5 (GSM)'),
            iPhoneModel(product_type='iPhone5,2', hardware_model='n42ap', board_id=0x02, chip_id=0x8950,
                        display_name='iPhone 5 (Global)'),
            iPhoneModel(product_type='iPhone5,3', hardware_model='n48ap', board_id=0x0a, chip_id=0x8950,
                        display_name='iPhone 5c (GSM)'),
            iPhoneModel(product_type='iPhone5,4', hardware_model='n49ap', board_id=0x0e, chip_id=0x8950,
                        display_name='iPhone 5c (Global)'),
            iPhoneModel(product_type='iPhone6,1', hardware_model='n51ap', board_id=0x00, chip_id=0x8960,
                        display_name='iPhone 5s (GSM)'),
            iPhoneModel(product_type='iPhone6,2', hardware_model='n53ap', board_id=0x02, chip_id=0x8960,
                        display_name='iPhone 5s (Global)'),
            iPhoneModel(product_type='iPhone7,1', hardware_model='n56ap', board_id=0x04, chip_id=0x7000,
                        display_name='iPhone 6 Plus'),
            iPhoneModel(product_type='iPhone7,2', hardware_model='n61ap', board_id=0x06, chip_id=0x7000,
                        display_name='iPhone 6'),
            iPhoneModel(product_type='iPhone8,1', hardware_model='n71ap', board_id=0x04, chip_id=0x8000,
                        display_name='iPhone 6s'),
            iPhoneModel(product_type='iPhone8,1', hardware_model='n71map', board_id=0x04, chip_id=0x8003,
                        display_name='iPhone 6s'),
            iPhoneModel(product_type='iPhone8,2', hardware_model='n66ap', board_id=0x06, chip_id=0x8000,
                        display_name='iPhone 6s Plus'),
            iPhoneModel(product_type='iPhone8,2', hardware_model='n66map', board_id=0x06, chip_id=0x8003,
                        display_name='iPhone 6s Plus'),
            iPhoneModel(product_type='iPhone8,4', hardware_model='n69ap', board_id=0x02, chip_id=0x8003,
                        display_name='iPhone SE'),
            iPhoneModel(product_type='iPhone8,4', hardware_model='n69uap', board_id=0x02, chip_id=0x8000,
                        display_name='iPhone SE'),
            iPhoneModel(product_type='iPhone9,1', hardware_model='d10ap', board_id=0x08, chip_id=0x8010,
                        display_name='iPhone 7 (Global)'),
            iPhoneModel(product_type='iPhone9,2', hardware_model='d11ap', board_id=0x0a, chip_id=0x8010,
                        display_name='iPhone 7 Plus (Global)'),
            iPhoneModel(product_type='iPhone9,3', hardware_model='d101ap', board_id=0x0c, chip_id=0x8010,
                        display_name='iPhone 7 (GSM)'),
            iPhoneModel(product_type='iPhone9,4', hardware_model='d111ap', board_id=0x0e, chip_id=0x8010,
                        display_name='iPhone 7 Plus (GSM)'),
            iPhoneModel(product_type='iPhone10,1', hardware_model='d20ap', board_id=0x02, chip_id=0x8015,
                        display_name='iPhone 8 (Global)'),
            iPhoneModel(product_type='iPhone10,2', hardware_model='d21ap', board_id=0x04, chip_id=0x8015,
                        display_name='iPhone 8 Plus (Global)'),
            iPhoneModel(product_type='iPhone10,3', hardware_model='d22ap', board_id=0x06, chip_id=0x8015,
                        display_name='iPhone X (Global)'),
            iPhoneModel(product_type='iPhone10,4', hardware_model='d201ap', board_id=0x0a, chip_id=0x8015,
                        display_name='iPhone 8 (GSM)'),
            iPhoneModel(product_type='iPhone10,5', hardware_model='d211ap', board_id=0x0c, chip_id=0x8015,
                        display_name='iPhone 8 Plus (GSM)'),
            iPhoneModel(product_type='iPhone10,6', hardware_model='d221ap', board_id=0x0e, chip_id=0x8015,
                        display_name='iPhone X (GSM)'),
            iPhoneModel(product_type='iPhone11,2', hardware_model='d321ap', board_id=0x0e, chip_id=0x8020,
                        display_name='iPhone XS'),
            iPhoneModel(product_type='iPhone11,4', hardware_model='d331ap', board_id=0x0a, chip_id=0x8020,
                        display_name='iPhone XS Max (China)'),
            iPhoneModel(product_type='iPhone11,6', hardware_model='d331pap', board_id=0x1a, chip_id=0x8020,
                        display_name='iPhone XS Max'),
            iPhoneModel(product_type='iPhone11,8', hardware_model='n841ap', board_id=0x0c, chip_id=0x8020,
                        display_name='iPhone XR'),
            iPhoneModel(product_type='iPhone12,1', hardware_model='n104ap', board_id=0x04, chip_id=0x8030,
                        display_name='iPhone 11'),
            iPhoneModel(product_type='iPhone12,3', hardware_model='d421ap', board_id=0x06, chip_id=0x8030,
                        display_name='iPhone 11 Pro'),
            iPhoneModel(product_type='iPhone12,5', hardware_model='d431ap', board_id=0x02, chip_id=0x8030,
                        display_name='iPhone 11 Pro Max'),
            iPhoneModel(product_type='iPhone12,8', hardware_model='d79ap', board_id=0x10, chip_id=0x8030,
                        display_name='iPhone SE (2020)'),
            iPhoneModel(product_type='iPhone13,1', hardware_model='d52gap', board_id=0x0A, chip_id=0x8101,
                        display_name='iPhone 12 mini'),
            iPhoneModel(product_type='iPhone13,2', hardware_model='d53gap', board_id=0x0C, chip_id=0x8101,
                        display_name='iPhone 12'),
            iPhoneModel(product_type='iPhone13,3', hardware_model='d53pap', board_id=0x0E, chip_id=0x8101,
                        display_name='iPhone 12 Pro'),
            iPhoneModel(product_type='iPhone13,4', hardware_model='d54pap', board_id=0x08, chip_id=0x8101,
                        display_name='iPhone 12 Pro Max'),
            iPhoneModel(product_type='iPhone14,2', hardware_model='d63ap', board_id=0x0C, chip_id=0x8110,
                        display_name='iPhone 13 Pro'),
            iPhoneModel(product_type='iPhone14,3', hardware_model='d64ap', board_id=0x0E, chip_id=0x8110,
                        display_name='iPhone 13 Pro Max'),
            iPhoneModel(product_type='iPhone14,4', hardware_model='d16ap', board_id=0x08, chip_id=0x8110,
                        display_name='iPhone 13 mini'),
            iPhoneModel(product_type='iPhone14,5', hardware_model='d17ap', board_id=0x0A, chip_id=0x8110,
                        display_name='iPhone 13'),
            iPhoneModel(product_type='iPhone14,6', hardware_model='d49ap', board_id=0x10, chip_id=0x8110,
                        display_name='iPhone SE (3rd gen)'),
            iPhoneModel(product_type='iPhone14,7', hardware_model='d27ap', board_id=0x18, chip_id=0x8110,
                        display_name='iPhone 14'),
            iPhoneModel(product_type='iPhone14,8', hardware_model='d28ap', board_id=0x1A, chip_id=0x8110,
                        display_name='iPhone 14 Plus'),
            iPhoneModel(product_type='iPhone15,2', hardware_model='d73ap', board_id=0x0C, chip_id=0x8120,
                        display_name='iPhone 14 Pro'),
            iPhoneModel(product_type='iPhone15,3', hardware_model='d74ap', board_id=0x0E, chip_id=0x8120,
                        display_name='iPhone 14 Pro Max'),
        ]

    def get_model(self, model_type: str) -> iPhoneModel:
        return list(filter(lambda model: model.product_type == model_type, self.__models))[0]
