from kivy.app import App
from kivy.uix.label import Label


class MyApp(App):
    def build(self):
        """
        实现父类的build()方法
        把build()方法实现为返回一个控件实例(这个控件的实例也就是你整个应用的根控件)
        :return:
        """

        # 在这个方法里面使用了Label控件
        return Label(text="Hello World!")


# 运行 Hello World
MyApp().run()
