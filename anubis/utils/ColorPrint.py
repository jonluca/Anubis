class ColorPrint:
  RED = '\033[91m'
  GREEN = '\033[92m'
  YELLOW = '\033[93m'
  LIGHT_PURPLE = '\033[94m'
  PURPLE = '\033[95m'
  END = '\033[0m'

  @classmethod
  def red(cls, s, **kwargs):
    print(cls.RED + s + cls.END, **kwargs)

  @classmethod
  def green(cls, s, **kwargs):
    print(cls.GREEN + s + cls.END, **kwargs)

  @classmethod
  def yellow(cls, s, **kwargs):
    print(cls.YELLOW + s + cls.END, **kwargs)

  @classmethod
  def light_purple(cls, s, **kwargs):
    print(cls.LIGHT_PURPLE + s + cls.END, **kwargs)

  @classmethod
  def purple(cls, s, **kwargs):
    print(cls.PURPLE + s + cls.END, **kwargs)
