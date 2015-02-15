# LSUUID_iOS
iOS设备唯一标识解决方法

解决方法是 获取UUID 存储到钥匙串中

使用方法
```
#import "UIDevice+LSUUID.h"
[UIDevice currentDevice].lsUUID
```
