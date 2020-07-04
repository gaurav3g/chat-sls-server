def formatter(arr):
    obj = {}
    for attr in arr:
        obj[attr["Name"]] = attr["Value"]

    return obj
